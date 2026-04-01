package main

type Company struct {
	ID                int
	Name              string
	TrialUntil        string
	SubscriptionUntil string
	IsActive          bool
	LeadUserID        int
	CreatedAt         string
}

type User struct {
	ID           int
	FullName     string
	Email        string
	PasswordHash string
	Role         string
	CompanyID    int
	CreatedAt    string
}

type Session struct {
	ID        int
	UserID    int
	Token     string
	ExpiresAt string
	CreatedAt string
}

type Client struct {
	ID        int
	CompanyID int
	Name      string
	Phone     string
	CarNumber string
	CarModel  string
}

type Order struct {
	ID          int
	CompanyID   int
	ClientID    int
	ClientName  string
	Service     string
	Price       float64
	PaymentType string
	Status      string
	CreatedAt   string
}

type Expense struct {
	ID        int
	CompanyID int
	Name      string
	Amount    float64
	CreatedAt string
}
