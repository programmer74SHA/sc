package http

import (
	"errors"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

// GetSwitches handles GET /api/v1/switches - List all switches
func GetSwitches(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		// Parse query parameters
		req := domain.SwitchListRequest{
			Limit: c.QueryInt("limit", 50),
			Page:  c.QueryInt("page", 0),
			Sort:  c.Query("sort", "name"),
			Order: c.Query("order", "asc"),
		}

		// Parse filters
		req.Filter = domain.SwitchFilter{
			Name:      c.Query("name", ""),
			Brand:     c.Query("brand", ""),
			IPAddress: c.Query("ip", ""),
			Status:    c.Query("status", ""),
		}

		// Parse scanner ID filter if provided
		if scannerIDStr := c.Query("scanner_id", ""); scannerIDStr != "" {
			if scannerID, err := strconv.ParseInt(scannerIDStr, 10, 64); err == nil {
				req.Filter.ScannerID = &scannerID
			}
		}

		// Handle filter[name] style parameters
		if filterName := c.Query("filter[name]", ""); filterName != "" {
			req.Filter.Name = filterName
		}
		if filterBrand := c.Query("filter[brand]", ""); filterBrand != "" {
			req.Filter.Brand = filterBrand
		}
		if filterIP := c.Query("filter[ip]", ""); filterIP != "" {
			req.Filter.IPAddress = filterIP
		}
		if filterStatus := c.Query("filter[status]", ""); filterStatus != "" {
			req.Filter.Status = filterStatus
		}

		logger.InfoContextWithFields(ctx, "Listing switches with request", map[string]interface{}{
			"limit":  req.Limit,
			"page":   req.Page,
			"sort":   req.Sort,
			"order":  req.Order,
			"filter": req.Filter,
		})

		// Call service
		response, err := srv.ListSwitches(ctx, req)
		if err != nil {
			logger.ErrorContext(ctx, "Error listing switches: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		logger.InfoContextWithFields(ctx, "Successfully listed switches", map[string]interface{}{
			"count": len(response.Switches),
		})

		// Build response in the format similar to other APIs
		result := map[string]interface{}{
			"data": map[string]interface{}{
				"contents": response.Switches,
				"count":    response.Count,
			},
			"switch": map[string]interface{}{
				"limit": req.Limit,
				"page":  req.Page,
				"sort": []map[string]string{
					{
						"field": req.Sort,
						"order": req.Order,
					},
				},
				"filter": map[string]interface{}{
					"name":       req.Filter.Name,
					"brand":      req.Filter.Brand,
					"ip_address": req.Filter.IPAddress,
					"status":     req.Filter.Status,
				},
			},
			"success": true,
		}

		return c.JSON(result)
	}
}

// GetSwitchByID handles GET /api/v1/switches/:id - Get switch details by ID
func GetSwitchByID(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		// Get switch ID from path parameter
		switchIDStr := c.Params("id")
		if switchIDStr == "" {
			logger.WarnContext(ctx, "Switch ID is empty")
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Switch ID is required",
			})
		}

		// Parse switch ID as UUID
		switchID, err := uuid.Parse(switchIDStr)
		if err != nil {
			logger.WarnContext(ctx, "Invalid switch ID format: %s", switchIDStr)
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Invalid switch ID format",
			})
		}

		logger.InfoContext(ctx, "Getting switch by ID: %s", switchID.String())

		// Call service
		response, err := srv.GetSwitchByID(ctx, switchID)
		if err != nil {
			logger.ErrorContext(ctx, "Error getting switch: %v", err)

			if err == service.ErrSwitchNotFound {
				return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
					Success: false,
					Error:   "Switch not found",
				})
			}

			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		logger.InfoContext(ctx, "Successfully retrieved switch: %s", response.Switch.Name)
		return c.JSON(response)
	}
}

// GetSwitchByScannerID handles GET /api/v1/switches/scanner/:id - Get switch by scanner ID
func GetSwitchByScannerID(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		// Get scanner ID from path parameter
		scannerIDStr := c.Params("id")
		if scannerIDStr == "" {
			logger.WarnContext(ctx, "Scanner ID is empty")
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Scanner ID is required",
			})
		}

		// Parse scanner ID
		scannerID, err := strconv.ParseInt(scannerIDStr, 10, 64)
		if err != nil {
			logger.WarnContext(ctx, "Invalid scanner ID format: %s", scannerIDStr)
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Invalid scanner ID format",
			})
		}

		logger.InfoContext(ctx, "Getting switch by scanner ID: %d", scannerID)

		// Call service
		response, err := srv.GetSwitchByScannerID(ctx, scannerID)
		if err != nil {
			logger.ErrorContext(ctx, "Error getting switch: %v", err)

			if err == service.ErrSwitchNotFound {
				return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
					Success: false,
					Error:   "Switch not found",
				})
			}

			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		logger.InfoContext(ctx, "Successfully retrieved switch for scanner: %d", scannerID)
		return c.JSON(response)
	}
}

// GetSwitchInterfaces handles GET /api/v1/switches/:id/interfaces - Get switch interfaces
func GetSwitchInterfaces(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		// Get switch ID from path parameter
		switchIDStr := c.Params("id")
		if switchIDStr == "" {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Switch ID is required",
			})
		}

		// Parse switch ID as UUID
		switchID, err := uuid.Parse(switchIDStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Invalid switch ID format",
			})
		}

		logger.InfoContext(ctx, "Getting interfaces for switch: %s", switchID.String())

		// Get switch with detailed data
		response, err := srv.GetSwitchByID(ctx, switchID)
		if err != nil {
			logger.ErrorContext(ctx, "Error getting switch: %v", err)

			if err == service.ErrSwitchNotFound {
				return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
					Success: false,
					Error:   "Switch not found",
				})
			}

			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		return c.JSON(map[string]interface{}{
			"data": map[string]interface{}{
				"interfaces": response.Switch.Interfaces,
				"count":      len(response.Switch.Interfaces),
			},
			"success": true,
		})
	}
}

// GetSwitchVLANs handles GET /api/v1/switches/:id/vlans - Get switch VLANs
func GetSwitchVLANs(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		// Get switch ID from path parameter
		switchIDStr := c.Params("id")
		if switchIDStr == "" {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Switch ID is required",
			})
		}

		// Parse switch ID as UUID
		switchID, err := uuid.Parse(switchIDStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Invalid switch ID format",
			})
		}

		logger.InfoContext(ctx, "Getting VLANs for switch: %s", switchID.String())

		// Get switch with detailed data
		response, err := srv.GetSwitchByID(ctx, switchID)
		if err != nil {
			logger.ErrorContext(ctx, "Error getting switch: %v", err)

			if err == service.ErrSwitchNotFound {
				return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
					Success: false,
					Error:   "Switch not found",
				})
			}

			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		return c.JSON(map[string]interface{}{
			"data": map[string]interface{}{
				"vlans": response.Switch.VLANs,
				"count": len(response.Switch.VLANs),
			},
			"success": true,
		})
	}
}

// GetSwitchNeighbors handles GET /api/v1/switches/:id/neighbors - Get switch neighbors
func GetSwitchNeighbors(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		// Get switch ID from path parameter
		switchIDStr := c.Params("id")
		if switchIDStr == "" {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Switch ID is required",
			})
		}

		// Parse switch ID as UUID
		switchID, err := uuid.Parse(switchIDStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Invalid switch ID format",
			})
		}

		logger.InfoContext(ctx, "Getting neighbors for switch: %s", switchID.String())

		// Get switch with detailed data
		response, err := srv.GetSwitchByID(ctx, switchID)
		if err != nil {
			logger.ErrorContext(ctx, "Error getting switch: %v", err)

			if err == service.ErrSwitchNotFound {
				return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
					Success: false,
					Error:   "Switch not found",
				})
			}

			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		return c.JSON(map[string]interface{}{
			"data": map[string]interface{}{
				"neighbors": response.Switch.Neighbors,
				"count":     len(response.Switch.Neighbors),
			},
			"success": true,
		})
	}
}

// GetSwitchStats handles GET /api/v1/switches/stats - Get switch statistics
func GetSwitchStats(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		logger.InfoContext(ctx, "Getting switch statistics")

		// Call service
		stats, err := srv.GetSwitchStats(ctx)
		if err != nil {
			logger.ErrorContext(ctx, "Error getting switch stats: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		logger.InfoContext(ctx, "Successfully retrieved switch statistics")

		return c.JSON(map[string]interface{}{
			"data":    stats,
			"success": true,
		})
	}
}

// CreateSwitch handles creation of a new switch via HTTP
func CreateSwitch(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		logger.InfoContext(ctx, "Switch creation request received")

		var req pb.CreateSwitchRequest
		if err := c.BodyParser(&req); err != nil {
			logger.WarnContext(ctx, "Failed to parse switch creation request body: %v", err)
			return fiber.ErrBadRequest
		}

		logger.DebugContextWithFields(ctx, "Switch creation request parsed successfully",
			map[string]interface{}{
				"switch_name":     req.GetAsset().GetName(),
				"management_ip":   req.GetDetails().GetManagementIp(),
				"vendor_code":     req.GetAsset().GetVendorCode(),
				"interface_count": len(req.GetInterfaces()),
				"vlan_count":      len(req.GetVlans()),
				"neighbor_count":  len(req.GetNeighbors()),
			})

		resp, err := srv.CreateSwitch(ctx, &req)
		if err != nil {
			if errors.Is(err, service.ErrSwitchManagementIPExists) {
				logger.WarnContext(ctx, "Switch creation failed: Management IP already exists for switch %s", req.GetAsset().GetName())
				return fiber.NewError(fiber.StatusConflict, "Management IP already exists")
			}
			if errors.Is(err, service.ErrVendorNotFound) {
				logger.WarnContext(ctx, "Switch creation failed: Vendor not found for switch %s", req.GetAsset().GetVendorCode())
				return fiber.NewError(fiber.StatusBadRequest, "Vendor not found")
			}
			if errors.Is(err, service.ErrInvalidSwitchData) {
				logger.WarnContext(ctx, "Switch creation failed: Invalid data for switch %s", req.GetAsset().GetName())
				return fiber.NewError(fiber.StatusBadRequest, "Invalid switch data")
			}
			logger.ErrorContext(ctx, "Switch creation failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContextWithFields(ctx, "Switch creation completed successfully", map[string]interface{}{
			"switch_id":   resp.GetId(),
			"switch_name": req.GetAsset().GetName(),
			"success":     resp.GetSuccess(),
		})

		return c.JSON(resp)
	}
}

// UpdateSwitch handles updating an existing switch via HTTP
func UpdateSwitch(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		switchID := c.Params("id")
		logger.InfoContext(ctx, "Switch update request received for ID: %s", switchID)

		if switchID == "" {
			logger.WarnContext(ctx, "Empty switch ID provided for update")
			return fiber.NewError(fiber.StatusBadRequest, "Switch ID is required")
		}

		var req pb.UpdateSwitchRequest
		if err := c.BodyParser(&req); err != nil {
			logger.WarnContext(ctx, "Failed to parse switch update request body: %v", err)
			return fiber.ErrBadRequest
		}

		req.Id = switchID

		logger.DebugContextWithFields(ctx, "Switch update request parsed successfully",
			map[string]interface{}{
				"switch_id":       switchID,
				"switch_name":     req.GetAsset().GetName(),
				"management_ip":   req.GetDetails().GetManagementIp(),
				"vendor_code":     req.GetAsset().GetVendorCode(),
				"interface_count": len(req.GetInterfaces()),
				"vlan_count":      len(req.GetVlans()),
				"neighbor_count":  len(req.GetNeighbors()),
			})

		resp, err := srv.UpdateSwitch(ctx, &req)
		if err != nil {
			if errors.Is(err, service.ErrSwitchNotFound) {
				logger.WarnContext(ctx, "Switch update failed: Switch not found with ID %s", switchID)
				return fiber.NewError(fiber.StatusNotFound, "Switch not found")
			}
			if errors.Is(err, service.ErrSwitchManagementIPExists) {
				logger.WarnContext(ctx, "Switch update failed: Management IP already exists for switch %s", switchID)
				return fiber.NewError(fiber.StatusConflict, "Management IP already exists")
			}
			if errors.Is(err, service.ErrVendorNotFound) {
				logger.WarnContext(ctx, "Switch update failed: Vendor not found for switch %s", switchID)
				return fiber.NewError(fiber.StatusBadRequest, "Vendor not found")
			}
			if errors.Is(err, service.ErrInvalidSwitchData) {
				logger.WarnContext(ctx, "Switch update failed: Invalid data for switch %s", switchID)
				return fiber.NewError(fiber.StatusBadRequest, "Invalid switch data")
			}
			if errors.Is(err, service.ErrInvalidSwitchUUID) {
				logger.WarnContext(ctx, "Switch update failed: Invalid UUID format for switch %s", switchID)
				return fiber.NewError(fiber.StatusBadRequest, "Invalid switch ID format")
			}
			logger.ErrorContext(ctx, "Switch update failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContextWithFields(ctx, "Switch update completed successfully", map[string]interface{}{
			"switch_id": switchID,
			"success":   resp.GetSuccess(),
		})

		return c.JSON(resp)
	}
}

// DeleteSwitch handles deletion of a switch
func DeleteSwitch(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		switchID := c.Params("id")
		logger.InfoContext(ctx, "Delete switch request received for ID: %s", switchID)

		if switchID == "" {
			logger.WarnContext(ctx, "Empty switch ID provided for delete")
			return fiber.NewError(fiber.StatusBadRequest, "Switch ID is required")
		}

		req := pb.DeleteSwitchRequest{
			Id: switchID,
		}

		logger.DebugContextWithFields(ctx, "Delete switch request parsed successfully",
			map[string]interface{}{
				"switch_id": switchID,
			})

		resp, err := srv.DeleteSwitch(ctx, &req)
		if err != nil {
			if errors.Is(err, service.ErrSwitchNotFound) {
				logger.WarnContext(ctx, "Switch delete failed: Switch not found with ID %s", switchID)
				return fiber.NewError(fiber.StatusNotFound, "Switch not found")
			}
			if errors.Is(err, service.ErrInvalidSwitchData) {
				logger.WarnContext(ctx, "Switch delete failed: Invalid data for switch %s", switchID)
				return fiber.NewError(fiber.StatusBadRequest, "Invalid switch data")
			}
			if errors.Is(err, service.ErrInvalidSwitchUUID) {
				logger.WarnContext(ctx, "Switch delete failed: Invalid UUID format for switch %s", switchID)
				return fiber.NewError(fiber.StatusBadRequest, "Invalid switch ID format")
			}
			logger.ErrorContext(ctx, "Switch delete failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContextWithFields(ctx, "Switch delete completed successfully", map[string]interface{}{
			"switch_id": switchID,
			"success":   resp.GetSuccess(),
		})

		return c.JSON(resp)
	}
}

// DeleteSwitches handles batch/all deletion of switches with exclude functionality
func DeleteSwitches(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		logger.InfoContext(ctx, "Delete switches request received")

		var req pb.DeleteSwitchesRequest
		if err := c.BodyParser(&req); err != nil {
			logger.WarnContext(ctx, "Failed to parse delete switches request body: %v", err)
			return fiber.ErrBadRequest
		}

		logger.DebugContextWithFields(ctx, "Delete switches request parsed successfully",
			map[string]interface{}{
				"ids_count": len(req.GetIds()),
				"exclude":   req.GetExclude(),
			})

		resp, err := srv.DeleteSwitches(ctx, &req)
		if err != nil {
			logger.ErrorContext(ctx, "Delete switches failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContextWithFields(ctx, "Delete switches completed successfully", map[string]interface{}{
			"success": resp.GetSuccess(),
		})

		return c.JSON(resp)
	}
}
