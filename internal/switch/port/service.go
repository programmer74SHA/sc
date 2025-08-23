package port

import (
	"context"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/domain"
)

// Service defines the interface for switch operations
type Service interface {
	// GetSwitchByID retrieves detailed information for a specific switch
	GetSwitchByID(ctx context.Context, switchID uuid.UUID) (*domain.SwitchInfo, error)

	// GetSwitchByScannerID retrieves detailed information for a switch by scanner ID
	GetSwitchByScannerID(ctx context.Context, scannerID int64) (*domain.SwitchInfo, error)

	// ListSwitches retrieves a list of switches with optional filtering and pagination
	ListSwitches(ctx context.Context, req domain.SwitchListRequest) (*domain.SwitchListResponse, error)

	// GetSwitchStats retrieves basic statistics about switches
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

	// DeleteSwitchesWithExclude deletes switches with exclude functionality
	DeleteSwitchesWithExclude(ctx context.Context, switchIDs []uuid.UUID, exclude bool) error
}
