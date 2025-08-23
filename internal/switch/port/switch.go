package port

import (
	"context"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/domain"
)

// Repository defines the interface for switch data persistence
type Repository interface {
	// GetSwitchByAssetID retrieves switch info by asset ID
	GetSwitchByAssetID(ctx context.Context, assetID uuid.UUID) (*domain.SwitchInfo, error)

	// GetSwitchByScannerID retrieves switch info by scanner ID
	GetSwitchByScannerID(ctx context.Context, scannerID int64) (*domain.SwitchInfo, error)

	// ListSwitches retrieves switches with filtering and pagination
	ListSwitches(ctx context.Context, filter domain.SwitchFilter, limit, offset int, sortField, sortOrder string) ([]domain.SwitchInfo, int, error)

	// GetSwitchStats retrieves aggregated switch statistics
	GetSwitchStats(ctx context.Context) (map[string]interface{}, error)

	// CreateSwitch creates a new switch
	CreateSwitch(ctx context.Context, switchData domain.Switch) (uuid.UUID, error)

	// UpdateSwitch updates an existing switch
	UpdateSwitch(ctx context.Context, switchID uuid.UUID, switchData domain.Switch) error

	// DeleteSwitch deletes a switch by ID
	DeleteSwitch(ctx context.Context, switchID uuid.UUID) error

	// DeleteSwitchBatch deletes multiple switches by IDs
	DeleteSwitchBatch(ctx context.Context, switchIDs []uuid.UUID) error

	// DeleteAllSwitches deletes all switches
	DeleteAllSwitches(ctx context.Context) error

	// DeleteAllSwitchesExcept deletes all switches except the specified ones
	DeleteAllSwitchesExcept(ctx context.Context, excludeSwitchIDs []uuid.UUID) error
}
