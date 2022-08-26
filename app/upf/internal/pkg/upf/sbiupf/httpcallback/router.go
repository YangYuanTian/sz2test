package httpcallback

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// Route is the information for every URI.
type Route struct {
	// DnnName is the name of this Route.
	Name string
	// Method is the string for the HTTP method. ex) GET, POST etc..
	Method string
	// Pattern is the pattern of the URI.
	Pattern string
	// HandlerFunc is the handler function of this route.
	HandlerFunc gin.HandlerFunc
}

// Routes is the list of the generated Route.
type Routes []Route

// NewRouter returns a new router.
func NewRouter(router *gin.Engine) *gin.Engine {
	//router := gin.Default()
	AddServiceNRFCallback(router)
	return router
}

func AddServiceNRFCallback(engine *gin.Engine) *gin.RouterGroup {
	group := engine.Group("")

	for _, route := range routesCallback {
		switch route.Method {
		case "GET":
			group.GET(route.Pattern, route.HandlerFunc)
		case "POST":
			group.POST(route.Pattern, route.HandlerFunc)
		case "PUT":
			group.PUT(route.Pattern, route.HandlerFunc)
		case "PATCH":
			group.PATCH(route.Pattern, route.HandlerFunc)
		case "DELETE":
			group.DELETE(route.Pattern, route.HandlerFunc)
		}
	}
	return group
}

var routesCallback = Routes{
	{
		"nf-status-notify",
		strings.ToUpper("POST"),
		"/notifications/nrf/nf-status/v1",
		NRFDiscoveryNotify,
	},
}
