package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/mcpgateway"
)

// runMCP manages the same per-user registry consumed by a connected Agent.
// Registry edits are picked up on the Agent's next MCP gateway request.
func runMCP(args []string) error {
	path := mcpgateway.DefaultPath()
	if len(args) == 0 {
		return errors.New("usage: chat-with-cli mcp list|add|remove|enable|disable|expose|hide|test")
	}
	command := args[0]
	rest := args[1:]
	if command == "test" {
		if len(rest) != 1 {
			return errors.New("usage: chat-with-cli mcp test <id>")
		}
		m := mcpgateway.New(path)
		defer m.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		n, err := m.Probe(ctx, rest[0])
		if err != nil {
			return err
		}
		fmt.Printf("%s: connected, %d tools\n", rest[0], n)
		return nil
	}
	registry, err := mcpgateway.Load(path)
	if err != nil {
		return err
	}
	switch command {
	case "list":
		if len(rest) != 0 {
			return errors.New("usage: chat-with-cli mcp list")
		}
		if len(registry.Servers) == 0 {
			fmt.Println("No downstream MCP servers configured.")
			return nil
		}
		for _, id := range mcpgateway.ServerIDs(registry) {
			cfg := registry.Servers[id]
			fmt.Printf("%-22s %-16s enabled=%-5t exposed=%-5t %s\n", id, cfg.Transport, cfg.Enabled, cfg.Expose, describeMCP(cfg))
		}
		return nil
	case "add":
		if len(rest) < 3 {
			return errors.New("usage: chat-with-cli mcp add <id> stdio <executable> [args...] | <id> http <URL>")
		}
		id := rest[0]
		if _, ok := registry.Servers[id]; ok {
			return fmt.Errorf("MCP server %q already exists", id)
		}
		cfg := mcpgateway.ServerConfig{Enabled: true, Expose: true}
		switch rest[1] {
		case "stdio":
			cfg.Transport, cfg.Command, cfg.Args = "stdio", rest[2], append([]string(nil), rest[3:]...)
		case "http":
			if len(rest) != 3 {
				return errors.New("HTTP transport takes exactly one URL")
			}
			cfg.Transport, cfg.URL = "streamable-http", rest[2]
		default:
			return errors.New("transport must be stdio or http")
		}
		registry.Servers[id] = cfg
	case "remove", "enable", "disable", "expose", "hide":
		if len(rest) != 1 {
			return fmt.Errorf("usage: chat-with-cli mcp %s <id>", command)
		}
		id := rest[0]
		cfg, ok := registry.Servers[id]
		if !ok {
			return fmt.Errorf("MCP server %q not found", id)
		}
		switch command {
		case "remove":
			delete(registry.Servers, id)
		case "enable":
			cfg.Enabled = true
		case "disable":
			cfg.Enabled = false
		case "expose":
			cfg.Expose = true
		case "hide":
			cfg.Expose = false
		}
		if command != "remove" {
			registry.Servers[id] = cfg
		}
	default:
		return fmt.Errorf("unknown MCP subcommand %q", command)
	}
	if err := mcpgateway.Save(path, registry); err != nil {
		return err
	}
	fmt.Printf("MCP registry updated: %s\n", strings.Join(args, " "))
	return nil
}

func describeMCP(cfg mcpgateway.ServerConfig) string {
	if cfg.Transport == "streamable-http" {
		return cfg.URL
	}
	args, _ := json.Marshal(cfg.Args)
	return fmt.Sprintf("%s %s", cfg.Command, args)
}
