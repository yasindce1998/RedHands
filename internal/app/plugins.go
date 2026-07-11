package app

import (
	"log"

	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/plugin"
)

func SetupPlugins(srv *mcp.Server, cfg *config.Config, execr executor.Executor) func() {
	pluginTools := plugin.LoadPlugins(cfg.PluginsDir, execr)
	for _, t := range pluginTools {
		srv.RegisterTool(t)
	}

	if cfg.PluginsDir == "" {
		return func() {}
	}

	watcher := plugin.NewWatcher(cfg.PluginsDir, cfg.PluginPollInterval, func(path string) error {
		newTools := plugin.LoadPlugins(cfg.PluginsDir, execr)
		for _, t := range newTools {
			srv.RegisterTool(t)
		}
		log.Printf("hot-reloaded plugins (trigger: %s)", path)
		return nil
	})
	watcher.Start()
	return watcher.Stop
}
