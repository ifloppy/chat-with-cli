package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"os"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const maxKWinRawBytes = 128 * 1024 * 1024

func kwinScreenshotServiceAvailable() bool {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return false
	}
	defer conn.Close()
	var owned bool
	call := conn.Object("org.freedesktop.DBus", "/org/freedesktop/DBus").
		Call("org.freedesktop.DBus.NameHasOwner", 0, "org.kde.KWin.ScreenShot2")
	return call.Err == nil && call.Store(&owned) == nil && owned
}
func variantInt(value dbus.Variant) (int, bool) {
	switch v := value.Value().(type) {
	case int32:
		return int(v), true
	case uint32:
		return int(v), true
	case int64:
		return int(v), true
	case uint64:
		if v > uint64(^uint(0)>>1) {
			return 0, false
		}
		return int(v), true
	default:
		return 0, false
	}
}

type kwinPipeResult struct {
	data []byte
	err  error
}

func readKWinPipe(file *os.File) <-chan kwinPipeResult {
	ch := make(chan kwinPipeResult, 1)
	go func() {
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, maxKWinRawBytes+1))
		if len(data) > maxKWinRawBytes {
			err = fmt.Errorf("KWin screenshot raw frame exceeds %d bytes", maxKWinRawBytes)
		}
		ch <- kwinPipeResult{data: data, err: err}
	}()
	return ch
}
func captureKWinWorkspace(ctx context.Context) (image.Image, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	readCh := readKWinPipe(reader)
	options := map[string]dbus.Variant{"include-cursor": dbus.MakeVariant(false)}
	var meta map[string]dbus.Variant
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	call := conn.Object("org.kde.KWin", "/org/kde/KWin/ScreenShot2").
		CallWithContext(callCtx, "org.kde.KWin.ScreenShot2.CaptureWorkspace", 0,
			options, dbus.UnixFD(writer.Fd()))
	cancel()
	_ = writer.Close()
	pipe := <-readCh
	if call.Err != nil {
		return nil, call.Err
	}
	if pipe.err != nil {
		return nil, pipe.err
	}
	if err := call.Store(&meta); err != nil {
		return nil, err
	}
	width, wok := variantInt(meta["width"])
	height, hok := variantInt(meta["height"])
	stride, sok := variantInt(meta["stride"])
	if !wok || !hok || !sok || width <= 0 || height <= 0 || stride < width*4 {
		return nil, fmt.Errorf("invalid KWin screenshot metadata: width=%d height=%d stride=%d", width, height, stride)
	}
	if format, ok := meta["format"]; ok {
		if value, valid := variantInt(format); valid && value != 6 {
			return nil, fmt.Errorf("unsupported KWin image format %d", value)
		}
	}
	need := stride * height
	if need < 0 || len(pipe.data) < need {
		return nil, errors.New("KWin screenshot returned a short frame")
	}
	return kwinBGRAToRGBA(pipe.data[:need], width, height, stride), nil
}
func kwinBGRAToRGBA(data []byte, width, height, stride int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		src := data[y*stride:]
		dst := img.Pix[y*img.Stride:]
		for x := 0; x < width; x++ {
			si, di := x*4, x*4
			dst[di] = src[si+2]
			dst[di+1] = src[si+1]
			dst[di+2] = src[si]
			dst[di+3] = src[si+3]
		}
	}
	return img
}

func encodeComputerImage(img image.Image, in ComputerScreenshotInput) (ComputerScreenshotOutput, error) {
	format := strings.ToLower(strings.TrimSpace(in.Format))
	if format == "" {
		format = "png"
	}
	bounds := img.Bounds()
	var out bytes.Buffer
	mime := "image/png"
	switch format {
	case "png":
		if err := png.Encode(&out, img); err != nil {
			return ComputerScreenshotOutput{}, err
		}
	case "jpg", "jpeg":
		quality := in.JPEGQuality
		if quality <= 0 {
			quality = 85
		}
		if quality < 1 || quality > 100 {
			return ComputerScreenshotOutput{}, errors.New("jpeg_quality must be between 1 and 100")
		}
		mime = "image/jpeg"
		if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: quality}); err != nil {
			return ComputerScreenshotOutput{}, err
		}
	default:
		return ComputerScreenshotOutput{}, fmt.Errorf("unsupported screenshot format %q", in.Format)
	}
	if out.Len() == 0 {
		return ComputerScreenshotOutput{}, errors.New("encoded screenshot is empty")
	}
	if out.Len() > maxScreenshotBytes {
		return ComputerScreenshotOutput{}, fmt.Errorf("encoded screenshot is too large: %d bytes", out.Len())
	}
	return ComputerScreenshotOutput{
		MIMEType: mime, Data: out.Bytes(), Width: bounds.Dx(), Height: bounds.Dy(),
	}, nil
}

func isKWinPermissionError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "not authorized") || strings.Contains(text, "access denied") || strings.Contains(text, "permission")
}

func (e *Engine) tryKWinScreenshot(ctx context.Context, in ComputerScreenshotInput) (ComputerScreenshotOutput, bool) {
	e.computerMu.Lock()
	disabled := e.kwinDBusDisabled
	e.computerMu.Unlock()
	if disabled || !kwinScreenshotServiceAvailable() {
		return ComputerScreenshotOutput{}, false
	}
	img, err := captureKWinWorkspace(ctx)
	if err != nil {
		if isKWinPermissionError(err) {
			e.computerMu.Lock()
			e.kwinDBusDisabled = true
			e.computerMu.Unlock()
		}
		return ComputerScreenshotOutput{}, false
	}
	out, err := encodeComputerImage(img, in)
	if err != nil {
		return ComputerScreenshotOutput{}, false
	}
	return out, true
}
