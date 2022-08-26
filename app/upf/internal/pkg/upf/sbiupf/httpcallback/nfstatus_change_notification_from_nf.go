package httpcallback

import (
	"github.com/gin-gonic/gin"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/openapi/models"
	"net/http"
)

func NRFDiscoveryNotify(c *gin.Context) {

	var NotifyData models.NotificationData
	if err := c.ShouldBindJSON(&NotifyData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{})
		return
	}

	rlogger.Trace(types.HttpCallback, rlogger.INFO, nil, "From:[%v] Event:[%v] State:[%v]",
		NotifyData.NfProfile.NfType, NotifyData.Event, NotifyData.NfProfile.NfStatus)

	c.JSON(http.StatusOK, gin.H{})
}
