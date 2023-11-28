package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"

	"github.com/google/uuid"
	"github.com/zale144/zkp-auth/proto"
	"github.com/zale144/zkp-auth/shared"
	"google.golang.org/grpc"
)

// UserAuthenticationData stores y1, y2, and the challenge 'c' for a user
type UserAuthenticationData struct {
	User string
	Y1   *big.Int
	Y2   *big.Int
	R1   *big.Int
	R2   *big.Int
	C    *big.Int
}

// AuthenticationService is the server that provides the authentication methods
type AuthenticationService struct {
	Users    sync.Map
	AuthData sync.Map
	Sessions sync.Map
	proto.UnimplementedAuthServer
}

// Register stores the user's public keys in the server's map
func (s *AuthenticationService) Register(_ context.Context, req *proto.RegisterRequest) (*proto.RegisterResponse, error) {
	userID := req.GetUser()
	if _, ok := s.Users.Load(userID); ok {
		return nil, fmt.Errorf("user already exists")
	}
	y1Str, ok := new(big.Int).SetString(fmt.Sprintf("%x", req.GetY1()), 16)
	if !ok {
		return nil, fmt.Errorf("error parsing y1")
	}
	y2Str, ok := new(big.Int).SetString(fmt.Sprintf("%x", req.GetY2()), 16)
	if !ok {
		return nil, fmt.Errorf("error parsing y2")
	}
	s.Users.Store(userID, UserAuthenticationData{User: userID, Y1: y1Str, Y2: y2Str})
	return &proto.RegisterResponse{}, nil
}

func (s *AuthenticationService) CreateAuthenticationChallenge(_ context.Context, req *proto.AuthenticationChallengeRequest) (*proto.AuthenticationChallengeResponse, error) {
	value, ok := s.Users.Load(req.GetUser())
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	authData := value.(UserAuthenticationData)

	// Generate a random challenge 'c'
	c, err := rand.Int(rand.Reader, shared.Q)
	if err != nil {
		return nil, fmt.Errorf("error generating challenge: %v", err)
	}

	authID := generateUniqueID()
	// Update authData with 'c', 'r1', and 'r2'
	authData.C = c
	authData.R1, ok = new(big.Int).SetString(fmt.Sprintf("%x", req.GetR1()), 16)
	if !ok {
		return nil, fmt.Errorf("error parsing r1")
	}
	authData.R2, ok = new(big.Int).SetString(fmt.Sprintf("%x", req.GetR2()), 16)
	if !ok {
		return nil, fmt.Errorf("error parsing r2")
	}
	s.AuthData.Store(authID, authData)

	return &proto.AuthenticationChallengeResponse{
		AuthId: authID,
		C:      c.Bytes(),
	}, nil
}

func (s *AuthenticationService) VerifyAuthentication(_ context.Context, req *proto.AuthenticationAnswerRequest) (*proto.AuthenticationAnswerResponse, error) {
	authId := req.GetAuthId()
	value, ok := s.AuthData.Load(authId)
	if !ok {
		return nil, fmt.Errorf("user not found")
	}

	authData := value.(UserAuthenticationData)
	sValue, ok := new(big.Int).SetString(fmt.Sprintf("%x", req.GetS()), 16)
	if !ok {
		return nil, fmt.Errorf("error parsing s")
	}

	// Verify the first equation: G^s * y1^c ?= r1
	gs := new(big.Int).Exp(shared.G, sValue, shared.P)
	y1c := new(big.Int).Exp(authData.Y1, authData.C, shared.P)
	leftSide := new(big.Int).Mul(gs, y1c)
	leftSide = leftSide.Mod(leftSide, shared.P)

	// Verify the second equation: H^s * y2^c ?= r2
	hs := new(big.Int).Exp(shared.H, sValue, shared.P)
	y2c := new(big.Int).Exp(authData.Y2, authData.C, shared.P)
	rightSide := new(big.Int).Mul(hs, y2c)
	rightSide = rightSide.Mod(rightSide, shared.P)

	// Check if both equations hold
	verified := leftSide.Cmp(authData.R1) == 0 && rightSide.Cmp(authData.R2) == 0
	if !verified {
		return &proto.AuthenticationAnswerResponse{
			SessionId: "",
		}, nil
	}

	s.AuthData.Delete(authId)
	sessionID := generateUniqueID()

	s.Sessions.Store(authData.User, sessionID)

	return &proto.AuthenticationAnswerResponse{
		SessionId: sessionID,
	}, nil
}

func generateUniqueID() string {
	return uuid.New().String()
}

func main() {
	portPtr := flag.String("port", "50051", "The server port")
	flag.Parse()
	port := ":" + *portPtr

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	proto.RegisterAuthServer(s, &AuthenticationService{})

	log.Println("Starting server on port " + port)

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
