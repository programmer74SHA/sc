package switch_scanner

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/domain"
	switchPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

// switchService implements the switch service interface
type switchService struct {
	repo       switchPort.Repository
	switchRepo SwitchDataRepository // Interface for switch data operations
}

// SwitchDataRepository defines operations for switch data (to avoid circular imports)
type SwitchDataRepository interface {
	GetSwitchByAssetID(ctx context.Context, assetID uuid.UUID) (*domain.SwitchInfo, error)
	GetSwitchByScannerID(ctx context.Context, scannerID int64) (*domain.SwitchInfo, error)
	ListSwitches(ctx context.Context, filter domain.SwitchFilter, limit, offset int, sortField, sortOrder string) ([]domain.SwitchInfo, int, error)
	GetSwitchStats(ctx context.Context) (map[string]interface{}, error)

	// Methods for detailed data
	GetSwitchDataByAssetID(ctx context.Context, assetID uuid.UUID) (*scannerDomain.SwitchData, error)

	// API methods
	CreateSwitch(ctx context.Context, switchData domain.Switch) (uuid.UUID, error)
	UpdateSwitch(ctx context.Context, switchID uuid.UUID, switchData domain.Switch) error
	DeleteSwitch(ctx context.Context, switchID uuid.UUID) error
	DeleteSwitchBatch(ctx context.Context, switchIDs []uuid.UUID) error
	DeleteAllSwitches(ctx context.Context) error
	DeleteAllSwitchesExcept(ctx context.Context, excludeSwitchIDs []uuid.UUID) error
}

// NewSwitchService creates a new switch service
func NewSwitchService(repo switchPort.Repository, switchRepo SwitchDataRepository) switchPort.Service {
	return &switchService{
		repo:       repo,
		switchRepo: switchRepo,
	}
}

// GetSwitchByID retrieves detailed information for a specific switch
func (s *switchService) GetSwitchByID(ctx context.Context, switchID uuid.UUID) (*domain.SwitchInfo, error) {
	logger.InfoContext(ctx, "[SwitchService] Getting switch by ID: %s", switchID.String())

	// Get basic switch info
	switchInfo, err := s.switchRepo.GetSwitchByAssetID(ctx, switchID)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchService] Error getting switch info: %v", err)
		return nil, fmt.Errorf("failed to get switch info: %w", err)
	}

	if switchInfo == nil {
		logger.InfoContext(ctx, "[SwitchService] Switch not found: %s", switchID.String())
		return nil, nil
	}

	// Get detailed switch data (interfaces, VLANs, neighbors)
	switchData, err := s.switchRepo.GetSwitchDataByAssetID(ctx, switchID)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchService] Warning: Could not get detailed switch data: %v", err)
		// Don't fail the request, just return basic info
	} else if switchData != nil {
		// Add detailed data to response
		switchInfo.Interfaces = switchData.Interfaces
		switchInfo.VLANs = switchData.VLANs
		switchInfo.Neighbors = switchData.Neighbors

		// Update counts with actual data
		switchInfo.NumberOfPorts = len(switchData.Interfaces)
		switchInfo.NumberOfVLANs = len(switchData.VLANs)
		switchInfo.NumberOfNeighbors = len(switchData.Neighbors)
	}

	logger.InfoContext(ctx, "[SwitchService] Successfully retrieved switch %s with %d interfaces, %d VLANs, %d neighbors",
		switchID.String(), switchInfo.NumberOfPorts, switchInfo.NumberOfVLANs, switchInfo.NumberOfNeighbors)

	return switchInfo, nil
}

// GetSwitchByScannerID retrieves detailed information for a switch by scanner ID
func (s *switchService) GetSwitchByScannerID(ctx context.Context, scannerID int64) (*domain.SwitchInfo, error) {
	logger.InfoContext(ctx, "[SwitchService] Getting switch by scanner ID: %d", scannerID)

	// Get basic switch info
	switchInfo, err := s.switchRepo.GetSwitchByScannerID(ctx, scannerID)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchService] Error getting switch info: %v", err)
		return nil, fmt.Errorf("failed to get switch info: %w", err)
	}

	if switchInfo == nil {
		logger.InfoContext(ctx, "[SwitchService] Switch not found for scanner: %d", scannerID)
		return nil, nil
	}

	// Parse asset ID to get detailed data
	assetID, err := uuid.Parse(switchInfo.ID)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchService] Invalid asset ID format: %s", switchInfo.ID)
		return switchInfo, nil // Return basic info without detailed data
	}

	// Get detailed switch data
	switchData, err := s.switchRepo.GetSwitchDataByAssetID(ctx, assetID)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchService] Warning: Could not get detailed switch data: %v", err)
	} else if switchData != nil {
		// Add detailed data to response
		switchInfo.Interfaces = switchData.Interfaces
		switchInfo.VLANs = switchData.VLANs
		switchInfo.Neighbors = switchData.Neighbors

		// Update counts with actual data
		switchInfo.NumberOfPorts = len(switchData.Interfaces)
		switchInfo.NumberOfVLANs = len(switchData.VLANs)
		switchInfo.NumberOfNeighbors = len(switchData.Neighbors)
	}

	logger.InfoContext(ctx, "[SwitchService] Successfully retrieved switch for scanner %d", scannerID)
	return switchInfo, nil
}

// ListSwitches retrieves a list of switches with optional filtering and pagination
func (s *switchService) ListSwitches(ctx context.Context, req domain.SwitchListRequest) (*domain.SwitchListResponse, error) {
	logger.InfoContext(ctx, "[SwitchService] Listing switches with request: %+v", req)

	// Set default pagination
	limit := req.Limit
	if limit <= 0 {
		limit = 50 // Default limit
	}
	if limit > 1000 {
		limit = 1000 // Max limit
	}

	page := req.Page
	if page < 0 {
		page = 0
	}

	offset := page * limit

	// Set default sorting
	sortField := req.Sort
	if sortField == "" {
		sortField = "name"
	}

	sortOrder := req.Order
	if sortOrder == "" {
		sortOrder = "asc"
	}

	// Validate sort order
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "asc"
	}

	// Get switches from repository
	switches, total, err := s.switchRepo.ListSwitches(ctx, req.Filter, limit, offset, sortField, sortOrder)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchService] Error listing switches: %v", err)
		return nil, fmt.Errorf("failed to list switches: %w", err)
	}

	response := &domain.SwitchListResponse{
		Switches: switches,
		Count:    total,
		Success:  true,
	}

	logger.InfoContext(ctx, "[SwitchService] Successfully listed %d switches (total: %d)", len(switches), total)
	return response, nil
}

// GetSwitchStats retrieves basic statistics about switches
func (s *switchService) GetSwitchStats(ctx context.Context) (map[string]interface{}, error) {
	logger.InfoContext(ctx, "[SwitchService] Getting switch statistics")

	stats, err := s.switchRepo.GetSwitchStats(ctx)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchService] Error getting switch stats: %v", err)
		return nil, fmt.Errorf("failed to get switch statistics: %w", err)
	}

	logger.InfoContext(ctx, "[SwitchService] Successfully retrieved switch statistics")
	return stats, nil
}

// CreateSwitch creates a new switch
func (s *switchService) CreateSwitch(ctx context.Context, switchData domain.Switch) (uuid.UUID, error) {
	logger.InfoContext(ctx, "[SwitchService] Creating new switch: %s", switchData.Name)

	switchID, err := s.switchRepo.CreateSwitch(ctx, switchData)
	if err != nil {
		logger.ErrorContext(ctx, "[SwitchService] Failed to create switch: %v", err)
		return uuid.Nil, fmt.Errorf("failed to create switch: %w", err)
	}

	logger.InfoContext(ctx, "[SwitchService] Successfully created switch with ID: %s", switchID.String())
	return switchID, nil
}

// UpdateSwitch updates an existing switch
func (s *switchService) UpdateSwitch(ctx context.Context, switchID uuid.UUID, switchData domain.Switch) error {
	logger.InfoContext(ctx, "[SwitchService] Updating switch: %s", switchID.String())

	err := s.switchRepo.UpdateSwitch(ctx, switchID, switchData)
	if err != nil {
		logger.ErrorContext(ctx, "[SwitchService] Failed to update switch: %v", err)
		return fmt.Errorf("failed to update switch: %w", err)
	}

	logger.InfoContext(ctx, "[SwitchService] Successfully updated switch with ID: %s", switchID.String())
	return nil
}

// DeleteSwitch deletes a switch by ID
func (s *switchService) DeleteSwitch(ctx context.Context, switchID uuid.UUID) error {
	logger.InfoContext(ctx, "[SwitchService] Deleting switch: %s", switchID.String())

	err := s.switchRepo.DeleteSwitch(ctx, switchID)
	if err != nil {
		logger.ErrorContext(ctx, "[SwitchService] Failed to delete switch: %v", err)
		return fmt.Errorf("failed to delete switch: %w", err)
	}

	logger.InfoContext(ctx, "[SwitchService] Successfully deleted switch with ID: %s", switchID.String())
	return nil
}

// DeleteSwitchBatch deletes multiple switches by IDs
func (s *switchService) DeleteSwitchBatch(ctx context.Context, switchIDs []uuid.UUID) error {
	logger.InfoContext(ctx, "[SwitchService] Deleting switches in batch: %d switches", len(switchIDs))

	err := s.switchRepo.DeleteSwitchBatch(ctx, switchIDs)
	if err != nil {
		logger.ErrorContext(ctx, "[SwitchService] Failed to delete switches in batch: %v", err)
		return fmt.Errorf("failed to delete switches in batch: %w", err)
	}

	logger.InfoContext(ctx, "[SwitchService] Successfully deleted %d switches in batch", len(switchIDs))
	return nil
}

// DeleteAllSwitches deletes all switches
func (s *switchService) DeleteAllSwitches(ctx context.Context) error {
	logger.InfoContext(ctx, "[SwitchService] Deleting all switches")

	err := s.switchRepo.DeleteAllSwitches(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "[SwitchService] Failed to delete all switches: %v", err)
		return fmt.Errorf("failed to delete all switches: %w", err)
	}

	logger.InfoContext(ctx, "[SwitchService] Successfully deleted all switches")
	return nil
}

// DeleteSwitchesWithExclude deletes switches with exclude functionality
func (s *switchService) DeleteSwitchesWithExclude(ctx context.Context, switchIDs []uuid.UUID, exclude bool) error {
	logger.InfoContextWithFields(ctx, "[SwitchService] Deleting switches with exclude logic", map[string]interface{}{
		"switch_count": len(switchIDs),
		"exclude":      exclude,
	})

	if exclude {
		if len(switchIDs) == 0 {
			// Delete all switches (exclude with empty IDs)
			logger.DebugContext(ctx, "[SwitchService] Deleting all switches (exclude with empty IDs)")
			return s.DeleteAllSwitches(ctx)
		}

		logger.DebugContext(ctx, "[SwitchService] Deleting all switches excluding specified IDs")
		err := s.switchRepo.DeleteAllSwitchesExcept(ctx, switchIDs)
		if err != nil {
			logger.ErrorContext(ctx, "[SwitchService] Failed to delete all except specified switches: %v", err)
			return fmt.Errorf("failed to delete all except specified switches: %w", err)
		}
	} else {
		if len(switchIDs) == 0 {
			// No switches to delete
			logger.DebugContext(ctx, "[SwitchService] No switches to delete (empty IDs list)")
			return nil
		}

		if len(switchIDs) == 1 {
			// Single deletion
			logger.DebugContext(ctx, "[SwitchService] Deleting single switch")
			return s.DeleteSwitch(ctx, switchIDs[0])
		}

		// Batch deletion
		logger.DebugContext(ctx, "[SwitchService] Deleting switches in batch")
		return s.DeleteSwitchBatch(ctx, switchIDs)
	}

	logger.InfoContext(ctx, "[SwitchService] Successfully deleted switches with exclude logic")
	return nil
}
