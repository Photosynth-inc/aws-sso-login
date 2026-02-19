package sso

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awssso "github.com/aws/aws-sdk-go-v2/service/sso"
)

// RoleCredentials holds temporary AWS credentials obtained via GetRoleCredentials.
type RoleCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// GetRoleCredentials retrieves scoped temporary credentials for a specific account/role.
func GetRoleCredentials(ctx context.Context, accessToken, accountID, roleName, ssoRegion string) (*RoleCredentials, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(ssoRegion),
		awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS config: %w", err)
	}

	client := awssso.NewFromConfig(cfg)
	out, err := client.GetRoleCredentials(ctx, &awssso.GetRoleCredentialsInput{
		AccessToken: &accessToken,
		AccountId:   &accountID,
		RoleName:    &roleName,
	})
	if err != nil {
		return nil, fmt.Errorf("GetRoleCredentials failed: %w", err)
	}

	return &RoleCredentials{
		AccessKeyID:     aws.ToString(out.RoleCredentials.AccessKeyId),
		SecretAccessKey:  aws.ToString(out.RoleCredentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.RoleCredentials.SessionToken),
		Expiration:      time.UnixMilli(out.RoleCredentials.Expiration),
	}, nil
}
