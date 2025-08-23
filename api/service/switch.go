package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/domain"
	switchPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

var (
	ErrSwitchNotFound           = errors.New("switch not found")
	ErrInvalidSwitchInput       = errors.New("invalid switch input")
	ErrSwitchCreateFailed       = errors.New("switch creation failed")
	ErrSwitchUpdateFailed       = errors.New("switch update failed")
	ErrSwitchDeleteFailed       = errors.New("switch delete failed")
	ErrInvalidSwitchData        = errors.New("invalid switch data")
	ErrSwitchManagementIPExists = errors.New("switch management IP already exists")
	ErrInvalidSwitchUUID        = errors.New("invalid switch UUID")
)

// SwitchService provides API operations for switches
type SwitchService struct {
	service switchPort.Service
}

// NewSwitchService creates a new SwitchService
func NewSwitchService(srv switchPort.Service) *SwitchService {
	return &SwitchService{
		service: srv,
	}
}

// GetSwitchByID retrieves detailed information for a specific switch
func (s *SwitchService) GetSwitchByID(ctx context.Context, switchID uuid.UUID) (*domain.SwitchDetailResponse, error) {
	logger.InfoContext(ctx, "API switch service: Getting switch by ID: %s", switchID.String())

	// Call internal service to get switch
	switchInfo, err := s.service.GetSwitchByID(ctx, switchID)
	if err != nil {
		logger.ErrorContext(ctx, "API switch service: Failed to get switch: %v", err)
		return &domain.SwitchDetailResponse{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	if switchInfo == nil {
		logger.WarnContext(ctx, "API switch service: Switch not found with ID: %s", switchID.String())
		return &domain.SwitchDetailResponse{
			Success: false,
			Error:   "Switch not found",
		}, ErrSwitchNotFound
	}

	logger.InfoContext(ctx, "API switch service: Successfully retrieved switch with ID: %s", switchID.String())
	return &domain.SwitchDetailResponse{
		Switch:  *switchInfo,
		Success: true,
	}, nil
}

// GetSwitchByScannerID retrieves detailed information for a switch by scanner ID
func (s *SwitchService) GetSwitchByScannerID(ctx context.Context, scannerID int64) (*domain.SwitchDetailResponse, error) {
	logger.InfoContext(ctx, "API switch service: Getting switch by scanner ID: %d", scannerID)

	// Call internal service to get switch
	switchInfo, err := s.service.GetSwitchByScannerID(ctx, scannerID)
	if err != nil {
		logger.ErrorContext(ctx, "API switch service: Failed to get switch: %v", err)
		return &domain.SwitchDetailResponse{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	if switchInfo == nil {
		logger.WarnContext(ctx, "API switch service: Switch not found for scanner ID: %d", scannerID)
		return &domain.SwitchDetailResponse{
			Success: false,
			Error:   "Switch not found",
		}, ErrSwitchNotFound
	}

	logger.InfoContext(ctx, "API switch service: Successfully retrieved switch for scanner ID: %d", scannerID)
	return &domain.SwitchDetailResponse{
		Switch:  *switchInfo,
		Success: true,
	}, nil
}

// ListSwitches retrieves a list of switches with optional filtering and pagination
func (s *SwitchService) ListSwitches(ctx context.Context, req domain.SwitchListRequest) (*domain.SwitchListResponse, error) {
	logger.InfoContextWithFields(ctx, "API switch service: Listing switches", map[string]interface{}{
		"limit": req.Limit,
		"page":  req.Page,
		"sort":  req.Sort,
		"order": req.Order,
	})

	// Call internal service to list switches
	response, err := s.service.ListSwitches(ctx, req)
	if err != nil {
		logger.ErrorContext(ctx, "API switch service: Failed to list switches: %v", err)
		return &domain.SwitchListResponse{
			Success: false,
		}, err
	}

	logger.InfoContextWithFields(ctx, "API switch service: Successfully listed switches", map[string]interface{}{
		"returned_count": len(response.Switches),
		"total_count":    response.Count,
	})

	return response, nil
}

// GetSwitchStats retrieves basic statistics about switches
func (s *SwitchService) GetSwitchStats(ctx context.Context) (map[string]interface{}, error) {
	logger.InfoContext(ctx, "API switch service: Getting switch statistics")

	// Call internal service to get switch stats
	stats, err := s.service.GetSwitchStats(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "API switch service: Failed to get switch stats: %v", err)
		return nil, err
	}

	logger.InfoContext(ctx, "API switch service: Successfully retrieved switch statistics")
	return stats, nil
}

// CreateSwitch handles creation of a new switch via API
func (s *SwitchService) CreateSwitch(ctx context.Context, req *pb.CreateSwitchRequest) (*pb.CreateSwitchResponse, error) {
	logger.InfoContextWithFields(ctx, "API switch service: Creating new switch", map[string]interface{}{
		"switch_name":     req.GetAsset().GetName(),
		"management_ip":   req.GetDetails().GetManagementIp(),
		"vendor_code":     req.GetAsset().GetVendorCode(),
		"interface_count": len(req.GetInterfaces()),
		"vlan_count":      len(req.GetVlans()),
		"neighbor_count":  len(req.GetNeighbors()),
	})

	logger.DebugContext(ctx, "API switch service: Converting protobuf request to domain model")
	switchDomain, err := s.convertPbToDomain(req)
	if err != nil {
		logger.ErrorContextWithFields(ctx, "API switch service: Failed to convert protobuf to domain", map[string]interface{}{
			"error":          err.Error(),
			"switch_name":    req.GetAsset().GetName(),
			"management_ip":  req.GetDetails().GetManagementIp(),
			"has_asset_id":   req.GetDetails().GetAssetId() != "",
			"asset_id_value": req.GetDetails().GetAssetId(),
		})
		return &pb.CreateSwitchResponse{
			Success: false,
			Message: "Invalid switch data: " + err.Error(),
		}, err
	}

	logger.DebugContext(ctx, "API switch service: Calling internal service to create switch")
	switchID, err := s.service.CreateSwitch(ctx, *switchDomain)
	if err != nil {
		if errors.Is(err, ErrSwitchManagementIPExists) {
			logger.WarnContext(ctx, "API switch service: Switch creation failed - Management IP already exists: %s", req.GetDetails().GetManagementIp())
			return &pb.CreateSwitchResponse{
				Success: false,
				Message: "Management IP already exists",
			}, err
		}
		if errors.Is(err, ErrVendorNotFound) {
			logger.WarnContext(ctx, "API switch service: Switch creation failed - Vendor not found: %s", req.GetAsset().GetVendorCode())
			return &pb.CreateSwitchResponse{
				Success: false,
				Message: "Vendor not found",
			}, err
		}
		if errors.Is(err, ErrInvalidSwitchData) {
			logger.WarnContext(ctx, "API switch service: Switch creation failed - Invalid data: %v", err)
			return &pb.CreateSwitchResponse{
				Success: false,
				Message: "Invalid switch data",
			}, err
		}
		logger.ErrorContext(ctx, "API switch service: Switch creation failed: %v", err)
		return &pb.CreateSwitchResponse{
			Success: false,
			Message: "Failed to create switch",
		}, err
	}

	logger.InfoContext(ctx, "API switch service: Successfully created switch with ID: %s", switchID.String())

	return &pb.CreateSwitchResponse{
		Id:      switchID.String(),
		Success: true,
		Message: "Switch created successfully",
	}, nil
}

// UpdateSwitch handles updating an existing switch via API
func (s *SwitchService) UpdateSwitch(ctx context.Context, req *pb.UpdateSwitchRequest) (*pb.UpdateSwitchResponse, error) {
	logger.InfoContextWithFields(ctx, "API switch service: Updating switch", map[string]interface{}{
		"switch_id":       req.GetId(),
		"switch_name":     req.GetAsset().GetName(),
		"management_ip":   req.GetDetails().GetManagementIp(),
		"vendor_code":     req.GetAsset().GetVendorCode(),
		"interface_count": len(req.GetInterfaces()),
		"vlan_count":      len(req.GetVlans()),
		"neighbor_count":  len(req.GetNeighbors()),
	})

	switchID, err := uuid.Parse(req.GetId())
	if err != nil {
		logger.WarnContext(ctx, "API switch service: Invalid switch ID format: %s", req.GetId())
		return &pb.UpdateSwitchResponse{
			Success: false,
			Message: "Invalid switch ID format",
		}, ErrInvalidSwitchUUID
	}

	logger.DebugContext(ctx, "API switch service: Converting protobuf request to domain model")
	switchDomain, err := s.convertPbToDomain(&pb.CreateSwitchRequest{
		Asset:        req.GetAsset(),
		Details:      req.GetDetails(),
		Interfaces:   req.GetInterfaces(),
		Vlans:        req.GetVlans(),
		Neighbors:    req.GetNeighbors(),
		RoutingTable: req.GetRoutingTable(),
	})
	if err != nil {
		logger.ErrorContextWithFields(ctx, "API switch service: Failed to convert protobuf to domain", map[string]interface{}{
			"error":       err.Error(),
			"switch_id":   req.GetId(),
			"switch_name": req.GetAsset().GetName(),
		})
		return &pb.UpdateSwitchResponse{
			Success: false,
			Message: "Invalid switch data: " + err.Error(),
		}, err
	}

	logger.DebugContext(ctx, "API switch service: Calling internal service to update switch")
	err = s.service.UpdateSwitch(ctx, switchID, *switchDomain)
	if err != nil {
		if errors.Is(err, ErrSwitchNotFound) {
			logger.WarnContext(ctx, "API switch service: Switch update failed - Switch not found: %s", req.GetId())
			return &pb.UpdateSwitchResponse{
				Success: false,
				Message: "Switch not found",
			}, err
		}
		if errors.Is(err, ErrSwitchManagementIPExists) {
			logger.WarnContext(ctx, "API switch service: Switch update failed - Management IP already exists: %s", req.GetDetails().GetManagementIp())
			return &pb.UpdateSwitchResponse{
				Success: false,
				Message: "Management IP already exists",
			}, err
		}
		if errors.Is(err, ErrVendorNotFound) {
			logger.WarnContext(ctx, "API switch service: Switch update failed - Vendor not found: %s", req.GetAsset().GetVendorCode())
			return &pb.UpdateSwitchResponse{
				Success: false,
				Message: "Vendor not found",
			}, err
		}
		if errors.Is(err, ErrInvalidSwitchData) {
			logger.WarnContext(ctx, "API switch service: Switch update failed - Invalid data: %v", err)
			return &pb.UpdateSwitchResponse{
				Success: false,
				Message: "Invalid switch data",
			}, err
		}
		logger.ErrorContext(ctx, "API switch service: Switch update failed: %v", err)
		return &pb.UpdateSwitchResponse{
			Success: false,
			Message: "Failed to update switch",
		}, err
	}

	logger.InfoContext(ctx, "API switch service: Successfully updated switch with ID: %s", req.GetId())

	return &pb.UpdateSwitchResponse{
		Success: true,
		Message: "Switch updated successfully",
	}, nil
}

// DeleteSwitch handles deletion of a switch via API
func (s *SwitchService) DeleteSwitch(ctx context.Context, req *pb.DeleteSwitchRequest) (*pb.DeleteSwitchResponse, error) {
	logger.InfoContext(ctx, "API switch service: Deleting switch with ID: %s", req.GetId())

	switchID, err := uuid.Parse(req.GetId())
	if err != nil {
		logger.WarnContext(ctx, "API switch service: Invalid switch ID format: %s", req.GetId())
		return &pb.DeleteSwitchResponse{
			Success: false,
			Message: "Invalid switch ID format",
		}, ErrInvalidSwitchUUID
	}

	logger.DebugContext(ctx, "API switch service: Calling internal service to delete switch")
	err = s.service.DeleteSwitch(ctx, switchID)
	if err != nil {
		if errors.Is(err, ErrSwitchNotFound) {
			logger.WarnContext(ctx, "API switch service: Switch delete failed - Switch not found: %s", req.GetId())
			return &pb.DeleteSwitchResponse{
				Success: false,
				Message: "Switch not found",
			}, err
		}
		logger.ErrorContext(ctx, "API switch service: Switch delete failed: %v", err)
		return &pb.DeleteSwitchResponse{
			Success: false,
			Message: "Failed to delete switch",
		}, err
	}

	logger.InfoContext(ctx, "API switch service: Successfully deleted switch with ID: %s", req.GetId())

	return &pb.DeleteSwitchResponse{
		Success: true,
		Message: "Switch deleted successfully",
	}, nil
}

// DeleteSwitches handles unified deletion of switches (single, batch, or all)
func (s *SwitchService) DeleteSwitches(ctx context.Context, req *pb.DeleteSwitchesRequest) (*pb.DeleteSwitchesResponse, error) {
	logger.InfoContextWithFields(ctx, "API switch service: Delete switches request received",
		map[string]interface{}{
			"ids_count": len(req.GetIds()),
			"exclude":   req.GetExclude(),
		})

	switchUUIDs := make([]uuid.UUID, 0, len(req.GetIds()))
	for _, id := range req.GetIds() {
		switchUUID, err := uuid.Parse(id)
		if err != nil {
			logger.WarnContext(ctx, "Invalid switch UUID format: %s", id)
			return &pb.DeleteSwitchesResponse{
				Success: false,
				Message: fmt.Sprintf("Invalid switch UUID format: %s", id),
			}, nil
		}
		switchUUIDs = append(switchUUIDs, switchUUID)
	}

	logger.DebugContext(ctx, "API switch service: Calling internal service to delete switches with exclude logic")
	err := s.service.DeleteSwitchesWithExclude(ctx, switchUUIDs, req.GetExclude())
	if err != nil {
		if errors.Is(err, ErrSwitchNotFound) {
			logger.WarnContext(ctx, "API switch service: Some switches not found")
			return &pb.DeleteSwitchesResponse{
				Success: false,
				Message: "Some switches not found",
			}, nil
		}
		logger.ErrorContext(ctx, "API switch service: Delete switches failed: %v", err)
		return &pb.DeleteSwitchesResponse{
			Success: false,
			Message: "Failed to delete switches",
		}, err
	}

	logger.InfoContext(ctx, "API switch service: Successfully deleted switches")
	return &pb.DeleteSwitchesResponse{
		Success: true,
		Message: "Switches deleted successfully",
	}, nil
}

// convertPbToDomain converts protobuf CreateSwitchRequest to domain.Switch
func (s *SwitchService) convertPbToDomain(req *pb.CreateSwitchRequest) (*domain.Switch, error) {
	if req.GetAsset() == nil {
		return nil, ErrInvalidSwitchData
	}

	if req.GetDetails() == nil {
		return nil, ErrInvalidSwitchData
	}

	// Validate required fields
	if req.GetAsset().GetName() == "" {
		return nil, errors.New("switch name is required")
	}

	if req.GetDetails().GetManagementIp() == "" {
		return nil, errors.New("management IP is required")
	}

	domainSwitch := &domain.Switch{
		VendorCode:  req.GetAsset().GetVendorCode(),
		Name:        req.GetAsset().GetName(),
		Domain:      req.GetAsset().GetDomain(),
		Hostname:    req.GetAsset().GetHostname(),
		OSName:      req.GetAsset().GetOsName(),
		OSVersion:   req.GetAsset().GetOsVersion(),
		Description: req.GetAsset().GetDescription(),
		AssetType:   req.GetAsset().GetAssetType(),

		ManagementIP:    req.GetDetails().GetManagementIp(),
		Model:           req.GetDetails().GetModel(),
		SoftwareVersion: req.GetDetails().GetSoftwareVersion(),
		SerialNumber:    req.GetDetails().GetSerialNumber(),
		SystemUptime:    req.GetDetails().GetSystemUptime(),
		EthernetMAC:     req.GetDetails().GetEthernetMac(),
		Location:        req.GetDetails().GetLocation(),
		Status:          req.GetDetails().GetStatus(),
		Brand:           req.GetDetails().GetBrand(),
		Username:        req.GetDetails().GetUsername(),
		Password:        req.GetDetails().GetPassword(),
		Port:            int(req.GetDetails().GetPort()),
	}

	if req.GetDetails().GetScannerId() != 0 {
		scannerID := req.GetDetails().GetScannerId()
		domainSwitch.ScannerID = &scannerID
	}

	if domainSwitch.AssetType == "" {
		domainSwitch.AssetType = "switch"
	}

	if domainSwitch.Status == "" {
		domainSwitch.Status = "active"
	}

	if domainSwitch.Port == 0 {
		domainSwitch.Port = 22
	}

	if req.GetInterfaces() != nil {
		for _, pbInterface := range req.GetInterfaces() {
			domainInterface := scannerDomain.SwitchInterface{
				Name:        pbInterface.GetInterfaceName(),
				Description: pbInterface.GetDescription(),
				IPAddress:   pbInterface.GetIpAddress(),
				SubnetMask:  pbInterface.GetSubnetMask(),
				Status:      pbInterface.GetStatus(),
				Protocol:    pbInterface.GetProtocol(),
				MacAddress:  pbInterface.GetMacAddress(),
				VLANs:       pbInterface.GetVlans(),
				Type:        pbInterface.GetType(),
				Speed:       pbInterface.GetSpeed(),
				Duplex:      pbInterface.GetDuplex(),
				MTU:         int(pbInterface.GetMtu()),
				Mode:        pbInterface.GetMode(),
			}
			domainSwitch.Interfaces = append(domainSwitch.Interfaces, domainInterface)
		}
	}

	if req.GetVlans() != nil {
		for _, pbVlan := range req.GetVlans() {
			domainVlan := scannerDomain.SwitchVLAN{
				ID:          int(pbVlan.GetVlanId()),
				Name:        pbVlan.GetVlanName(),
				Description: pbVlan.GetDescription(),
				Status:      pbVlan.GetStatus(),
				Ports:       pbVlan.GetPorts(),
				Type:        pbVlan.GetType(),
				Parent:      int(pbVlan.GetParent()),
				Gateway:     pbVlan.GetGateway(),
				Subnet:      pbVlan.GetSubnet(),
			}
			domainSwitch.VLANs = append(domainSwitch.VLANs, domainVlan)
		}
	}

	if req.GetNeighbors() != nil {
		for _, pbNeighbor := range req.GetNeighbors() {
			domainNeighbor := scannerDomain.SwitchNeighbor{
				DeviceID:     pbNeighbor.GetDeviceId(),
				LocalPort:    pbNeighbor.GetLocalPort(),
				RemotePort:   pbNeighbor.GetRemotePort(),
				Platform:     pbNeighbor.GetPlatform(),
				IPAddress:    pbNeighbor.GetIpAddress(),
				Capabilities: pbNeighbor.GetCapabilities(),
				Software:     pbNeighbor.GetSoftware(),
				Duplex:       pbNeighbor.GetDuplex(),
				Protocol:     pbNeighbor.GetProtocol(),
			}
			domainSwitch.Neighbors = append(domainSwitch.Neighbors, domainNeighbor)
		}
	}

	if req.GetRoutingTable() != nil {
		for _, pbRoute := range req.GetRoutingTable() {
			domainRoute := scannerDomain.SwitchRoutingEntry{
				Network:         pbRoute.GetNetwork(),
				Mask:            pbRoute.GetMask(),
				NextHop:         pbRoute.GetNextHop(),
				Interface:       pbRoute.GetInterface(),
				Metric:          int(pbRoute.GetMetric()),
				AdminDistance:   int(pbRoute.GetAdminDistance()),
				Protocol:        pbRoute.GetProtocol(),
				Age:             pbRoute.GetAge(),
				Tag:             pbRoute.GetTag(),
				VRF:             pbRoute.GetVrf(),
				RoutePreference: int(pbRoute.GetRoutePreference()),
			}
			domainSwitch.RoutingTable = append(domainSwitch.RoutingTable, domainRoute)
		}
	}

	return domainSwitch, nil
}
