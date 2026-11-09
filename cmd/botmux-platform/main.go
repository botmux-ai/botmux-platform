// Command botmux-platform serves the Botmux platform: Feishu sign-in, the
// reverse tunnel to each machine's dashboard, and team collaboration.
//
// Infrastructure is configured through the environment: MONGODB_URI (durable
// store; in-memory when unset) and REDIS_URL (cross-replica coordination;
// required only when running more than one replica).
package main

import (
	"log/slog"
	"os"

	"github.com/botmux-ai/botmux-platform/internal/runner"
)

func main() {
	if err := runner.Run(runner.Options{}); err != nil {
		slog.Error("botmux platform stopped", "error", err)
		os.Exit(1)
	}
}
