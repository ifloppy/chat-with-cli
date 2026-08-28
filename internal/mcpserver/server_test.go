package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/ifloppy/chat-with-cli/internal/engine"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeCaller struct {
	shot    engine.ComputerScreenshotOutput
	observe engine.ComputerObserveOutput
}

func (f fakeCaller) Call(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
	switch method {
	case "computer_screenshot":
		return json.Marshal(f.shot)
	case "computer_observe":
		return json.Marshal(f.observe)
	default:
		return json.Marshal(engine.Ack{OK: true})
	}
}

func tinyPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 1, G: 2, B: 3, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestScreenshotToolReturnsImageContent(t *testing.T) {
	ctx := context.Background()
	pngData := tinyPNG(t)
	server := New(fakeCaller{shot: engine.ComputerScreenshotOutput{
		MIMEType: "image/png", Data: pngData, Width: 1, Height: 1,
	}})
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name:      "computer_screenshot",
		Arguments: map[string]any{"format": "png"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Content) != 1 {
		t.Fatalf("content count=%d", len(result.Content))
	}
	imageContent, ok := result.Content[0].(*mcp.ImageContent)
	if !ok {
		t.Fatalf("content type=%T", result.Content[0])
	}
	if imageContent.MIMEType != "image/png" {
		t.Fatalf("mime=%q", imageContent.MIMEType)
	}
	if !bytes.Equal(imageContent.Data, pngData) {
		t.Fatal("image bytes changed in MCP transport")
	}
	meta, ok := result.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structured content type=%T", result.StructuredContent)
	}
	if meta["width"] != float64(1) || meta["height"] != float64(1) {
		t.Fatalf("bad dimensions: %#v", meta)
	}
}

func TestObserveToolReturnsSemanticMetaAndOptionalImage(t *testing.T) {
	ctx := context.Background()
	pngData := tinyPNG(t)
	server := New(fakeCaller{observe: engine.ComputerObserveOutput{
		Info:             engine.ComputerInfoOutput{ScreenAllowed: true},
		UI:               engine.ComputerUIQueryOutput{Visited: 7, Nodes: []engine.ComputerUINode{{Name: "Build", Role: "push button"}}},
		Screenshot:       &engine.ComputerScreenshotOutput{MIMEType: "image/png", Data: pngData, Width: 1, Height: 1},
		ScreenshotReason: "requested",
	}})
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: "computer_observe", Arguments: map[string]any{"screenshot": "always"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Content) != 1 {
		t.Fatalf("content count=%d", len(result.Content))
	}
	imageContent, ok := result.Content[0].(*mcp.ImageContent)
	if !ok || !bytes.Equal(imageContent.Data, pngData) {
		t.Fatalf("bad image content: %T", result.Content[0])
	}
	meta, ok := result.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structured content type=%T", result.StructuredContent)
	}
	if meta["screenshot_reason"] != "requested" {
		t.Fatalf("bad meta: %#v", meta)
	}
	ui, ok := meta["ui"].(map[string]any)
	if !ok || ui["visited"] != float64(7) {
		t.Fatalf("bad ui meta: %#v", meta["ui"])
	}
}

func TestHighLevelComputerToolsAreAdvertisedWithSafetyHints(t *testing.T) {
	ctx := context.Background()
	server := New(fakeCaller{})
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	listed, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]*mcp.Tool{}
	for _, tool := range listed.Tools {
		tools[tool.Name] = tool
	}
	observe := tools["computer_observe"]
	if observe == nil || observe.Annotations == nil || !observe.Annotations.ReadOnlyHint {
		t.Fatalf("computer_observe missing read-only annotation: %#v", observe)
	}
	for _, name := range []string{"computer_ui_invoke", "computer_ui_set_text"} {
		tool := tools[name]
		if tool == nil || tool.Annotations == nil {
			t.Fatalf("%s missing", name)
		}
		if tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint {
			t.Fatalf("%s missing destructive hint", name)
		}
		if tool.Annotations.OpenWorldHint == nil || !*tool.Annotations.OpenWorldHint {
			t.Fatalf("%s missing open-world hint", name)
		}
	}
}
