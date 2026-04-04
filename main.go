package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	initDB()
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/login", loginPageHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/owner/dashboard", ownerDashboardHandler)
	http.HandleFunc("/owner/leads", ownerLeadsHandler)
	http.HandleFunc("/owner/leads/add", ownerLeadAddHandler)
	http.HandleFunc("/owner/companies/view", ownerCompanyDetailHandler)
	http.HandleFunc("/owner/companies/toggle", ownerCompanyToggleHandler)
	http.HandleFunc("/owner/companies/extend", ownerCompanyExtendHandler)
	http.HandleFunc("/owner/companies/pay", ownerCompanyPayHandler)
	http.HandleFunc("/lead/dashboard", leadDashboardHandler)
	http.HandleFunc("/lead/companies/add", leadCompanyAddHandler)
	http.HandleFunc("/lead/companies/access", leadCompanyAccessHandler)
	http.HandleFunc("/lead/income", leadIncomeHandler)

	http.HandleFunc("/", dashboardHandler)
	http.HandleFunc("/clients", clientsHandler)
	http.HandleFunc("/clients/add", clientAddHandler)
	http.HandleFunc("/clients/view", clientDetailHandler)
	http.HandleFunc("/clients/edit", clientEditHandler)
	http.HandleFunc("/clients/delete", clientDeleteHandler)
	http.HandleFunc("/orders", ordersHandler)
	http.HandleFunc("/orders/add", orderAddHandler)
	http.HandleFunc("/orders/edit", orderEditHandler)
	http.HandleFunc("/orders/delete", orderDeleteHandler)
	http.HandleFunc("/expenses", expensesHandler)
	http.HandleFunc("/expenses/add", expenseAddHandler)
	http.HandleFunc("/expenses/edit", expenseEditHandler)
	http.HandleFunc("/expenses/delete", expenseDeleteHandler)
	http.HandleFunc("/owner/leads/view", ownerLeadDetailHandler)
	http.HandleFunc("/owner/leads/delete", ownerLeadDeleteHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Println("Server running on port:", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
