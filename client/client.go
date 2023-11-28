package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/zale144/zkp-auth/proto"
	"github.com/zale144/zkp-auth/shared"
	"google.golang.org/grpc"
)

const timeout = 10 * time.Second

func main() {
	if len(os.Args) < 2 {
		fmt.Println("subcommand is required")
		os.Exit(1)
	}

	serverAddr, userID, secret, err := flags(os.Args[1])
	if err != nil {
		fmt.Printf("could not parse flags: %v\n", err)
		os.Exit(1)
	}

	conn, err := grpc.Dial(serverAddr, grpc.WithInsecure())
	if err != nil {
		fmt.Printf("could not connect to server: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := proto.NewAuthClient(conn)
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch os.Args[1] {
	case "register":
		if err := register(ctx, client, secret, userID); err != nil {
			fmt.Printf("could not register user: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("user registered successfully")
	case "login":
		// Step 0: Generate random value k
		k, err := rand.Int(rand.Reader, shared.Q)
		if err != nil {
			fmt.Printf("could not generate random value: %v\n", err)
			os.Exit(1)
		}

		// Step 1: Start authentication challenge
		challenge, authId, err := startAuthenticationChallenge(ctx, client, userID, k)
		if err != nil {
			fmt.Printf("could not start authentication challenge: %v\n", err)
			os.Exit(1)
		}
		c, ok := new(big.Int).SetString(fmt.Sprintf("%x", challenge), 16)
		if !ok {
			fmt.Println("could not parse challenge")
			os.Exit(1)
		}
		// Step 2: Verify authentication
		if err := verifyAuthentication(ctx, client, authId, secret, k, c); err != nil {
			fmt.Printf("could not verify authentication: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Println("unknown subcommand")
		os.Exit(1)
	}
}

func register(ctx context.Context, client proto.AuthClient, x *big.Int, userID string) error {
	// Calculate y1 and y2 based on the secret x and the generator g and h
	y1 := new(big.Int).Exp(shared.G, x, shared.P)
	y2 := new(big.Int).Exp(shared.H, x, shared.P)
	_, err := client.Register(ctx, &proto.RegisterRequest{
		User: userID,
		Y1:   y1.Bytes(),
		Y2:   y2.Bytes(),
	})
	if err != nil {
		return fmt.Errorf("could not register user: %v", err)
	}
	return nil
}

func startAuthenticationChallenge(ctx context.Context, client proto.AuthClient, user string, k *big.Int) ([]byte, string, error) {
	// Calculate r1 and r2 based on the random value k and the generator g and h
	r1 := new(big.Int).Exp(shared.G, k, shared.P)
	r2 := new(big.Int).Exp(shared.H, k, shared.P)
	challengeResponse, err := client.CreateAuthenticationChallenge(ctx, &proto.AuthenticationChallengeRequest{
		User: user,
		R1:   r1.Bytes(),
		R2:   r2.Bytes(),
	})
	if err != nil {
		return nil, "", fmt.Errorf("could not create authentication challenge: %v", err)
	}
	return challengeResponse.C, challengeResponse.AuthId, nil
}

func verifyAuthentication(ctx context.Context, client proto.AuthClient, authId string, x, k, c *big.Int) error {
	s := new(big.Int).Sub(k, new(big.Int).Mul(c, x))
	s = s.Mod(s, shared.Q)

	verifyResponse, err := client.VerifyAuthentication(ctx, &proto.AuthenticationAnswerRequest{
		AuthId: authId,
		S:      s.Bytes(),
	})
	if err != nil {
		return fmt.Errorf("could not verify authentication: %v", err)
	}

	if verifyResponse.GetSessionId() == "" {
		fmt.Println("authentication failed")
	} else {
		fmt.Println("Session ID:", verifyResponse.GetSessionId())
	}
	return nil
}

func flags(cmd string) (string, string, *big.Int, error) {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	secretStr := fs.String("secret", "", "The secret value for the registration process")
	serverAddr := fs.String("server", "localhost:50051", "The server address in the format of host:port")
	user := fs.String("user", "", "The user ID to register or authenticate")

	if err := fs.Parse(os.Args[2:]); err != nil {
		return "", "", nil, fmt.Errorf("could not parse flags: %v", err)
	}

	if *secretStr == "" {
		return "", "", nil, fmt.Errorf("secret cannot be empty")
	}

	hasher := sha256.New()
	hasher.Write([]byte(*secretStr))
	hashBytes := hasher.Sum(nil)
	secret := new(big.Int).SetBytes(hashBytes)

	return *serverAddr, *user, secret, nil
}
