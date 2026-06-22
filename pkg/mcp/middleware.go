package mcp

type Middleware func(next ToolHandler) ToolHandler

func chainMiddleware(handler ToolHandler, middlewares []Middleware) ToolHandler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}
