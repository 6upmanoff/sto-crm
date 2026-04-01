package main

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	files := []string{
		"templates/base.html",
		"templates/" + tmpl,
	}

	t, err := template.ParseFiles(files...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = t.ExecuteTemplate(w, "base", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func getCurrentUser(r *http.Request) (*User, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return nil, err
	}

	var user User
	err = db.QueryRow(`
		SELECT u.id, u.full_name, u.email, u.password_hash, u.role, COALESCE(u.company_id, 0),
		       TO_CHAR(u.created_at, 'DD.MM.YYYY HH24:MI')
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token = $1 AND s.expires_at > NOW()
	`, cookie.Value).Scan(
		&user.ID,
		&user.FullName,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.CompanyID,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func requireAuth(w http.ResponseWriter, r *http.Request) (*User, bool) {
	user, err := getCurrentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, false
	}
	return user, true
}

func requireRole(w http.ResponseWriter, r *http.Request, allowedRoles ...string) (*User, bool) {
	user, ok := requireAuth(w, r)
	if !ok {
		return nil, false
	}

	for _, role := range allowedRoles {
		if user.Role == role {
			return user, true
		}
	}

	http.Error(w, "Доступ запрещён", http.StatusForbidden)
	return nil, false
}

func requireActiveClientAccess(w http.ResponseWriter, r *http.Request) (*User, bool) {
	user, ok := requireRole(w, r, "client")
	if !ok {
		return nil, false
	}

	var isAllowed bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1
			FROM companies
			WHERE id = $1
			  AND is_active = true
			  AND (
				(trial_until IS NOT NULL AND trial_until >= CURRENT_DATE)
				OR
				(subscription_until IS NOT NULL AND subscription_until >= CURRENT_DATE)
			  )
		)
	`, user.CompanyID).Scan(&isAllowed)
	if err != nil {
		http.Error(w, "Ошибка проверки доступа компании", http.StatusInternalServerError)
		return nil, false
	}

	if !isAllowed {
		renderCompanyAccessDenied(w)
		return nil, false
	}

	return user, true
}

func renderCompanyAccessDenied(w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Доступ недоступен</title>
  <style>
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f8fafc;
      color: #0f172a;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 24px;
      box-sizing: border-box;
    }
    .card {
      width: 100%;
      max-width: 560px;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 20px;
      box-shadow: 0 20px 40px rgba(15, 23, 42, 0.08);
      padding: 28px;
      box-sizing: border-box;
    }
    .badge {
      display: inline-block;
      margin-bottom: 14px;
      padding: 6px 10px;
      border-radius: 999px;
      background: #fef2f2;
      border: 1px solid #fecaca;
      color: #b91c1c;
      font-size: 13px;
      font-weight: 700;
    }
    h1 {
      margin: 0 0 10px 0;
      font-size: 28px;
      line-height: 1.2;
    }
    p {
      margin: 0 0 12px 0;
      line-height: 1.6;
      color: #475569;
      font-size: 15px;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 18px;
    }
    .actions a {
      display: inline-block;
      text-decoration: none;
      padding: 10px 14px;
      border-radius: 10px;
      font-weight: 600;
      font-size: 14px;
      border: 1px solid #cbd5e1;
      color: #0f172a;
      background: #ffffff;
    }
    .actions a.primary {
      background: #0f172a;
      border-color: #0f172a;
      color: #ffffff;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">Доступ ограничен</div>
    <h1>Компания временно недоступна</h1>
    <p>Доступ в систему для этой компании сейчас отключён либо срок пробного или оплаченного периода уже закончился.</p>
    <p>Обратитесь к владельцу системы или ответственному Lead, чтобы продлить доступ и снова активировать компанию.</p>
    <div class="actions">
      <a href="/logout">Выйти</a>
      <a href="/login" class="primary">На страницу входа</a>
    </div>
  </div>
</body>
</html>`))
}

func currentCompanyID(r *http.Request) int {
	user, err := getCurrentUser(r)
	if err != nil {
		// Временный fallback, пока не закрыли все маршруты через requireAuth.
		return 1
	}

	if user.CompanyID > 0 {
		return user.CompanyID
	}

	return 1
}

func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func createSession(w http.ResponseWriter, userID int) error {
	token, err := generateSessionToken()
	if err != nil {
		return err
	}

	expiresAt := time.Now().Add(24 * time.Hour)

	_, err = db.Exec(`
		INSERT INTO sessions (user_id, token, expires_at)
		VALUES ($1, $2, $3)
	`, userID, token, expiresAt)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Expires:  expiresAt,
	})

	return nil
}

func hashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func checkPassword(password string, storedHash string) bool {
	if storedHash == "" {
		return false
	}

	// Новый безопасный путь: bcrypt.
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)); err == nil {
		return true
	}

	// Временная обратная совместимость для старых/demo-пользователей,
	// у которых пароль пока хранится в открытом виде.
	return password == storedHash
}

func redirectPathByRole(role string) string {
	switch role {
	case "lead":
		return "/lead/dashboard"
	case "owner":
		return "/owner/dashboard"
	case "client":
		return "/"
	default:
		return "/"
	}
}

func loginActionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		data := map[string]interface{}{
			"Title": "Вход",
		}
		renderTemplate(w, "login.html", data)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	var user User
	err := db.QueryRow(`
		SELECT id, full_name, email, password_hash, role, COALESCE(company_id, 0), TO_CHAR(created_at, 'DD.MM.YYYY HH24:MI')
		FROM users
		WHERE email = $1
	`, email).Scan(
		&user.ID,
		&user.FullName,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.CompanyID,
		&user.CreatedAt,
	)
	if err != nil {
		data := map[string]interface{}{
			"Title": "Вход",
			"Error": "Пользователь не найден",
		}
		renderTemplate(w, "login.html", data)
		return
	}

	valid := checkPassword(password, user.PasswordHash)

	if !valid {
		data := map[string]interface{}{
			"Title": "Вход",
			"Error": "Неверный пароль",
		}
		renderTemplate(w, "login.html", data)
		return
	}

	err = createSession(w, user.ID)
	if err != nil {
		http.Error(w, "Ошибка создания сессии", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectPathByRole(user.Role), http.StatusSeeOther)
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	loginActionHandler(w, r)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		_, _ = db.Exec(`DELETE FROM sessions WHERE token = $1`, cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func leadDashboardHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := requireRole(w, r, "lead", "owner")
	if !ok {
		return
	}

	rows, err := db.Query(`
		SELECT id, name,
		       COALESCE(TO_CHAR(trial_until, 'DD.MM.YYYY'), ''),
		       COALESCE(TO_CHAR(subscription_until, 'DD.MM.YYYY'), ''),
		       is_active,
		       COALESCE(lead_user_id, 0),
		       TO_CHAR(created_at, 'DD.MM.YYYY HH24:MI')
		FROM companies
		WHERE lead_user_id = $1
		ORDER BY id DESC
	`, user.ID)
	if err != nil {
		http.Error(w, "Ошибка загрузки компаний", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var companies []map[string]interface{}
	for rows.Next() {
		var c Company
		err := rows.Scan(
			&c.ID,
			&c.Name,
			&c.TrialUntil,
			&c.SubscriptionUntil,
			&c.IsActive,
			&c.LeadUserID,
			&c.CreatedAt,
		)
		if err != nil {
			http.Error(w, "Ошибка чтения компаний", http.StatusInternalServerError)
			return
		}

		var clientCount int
		err = db.QueryRow(`
			SELECT COUNT(*)
			FROM users
			WHERE company_id = $1 AND role = 'client'
		`, c.ID).Scan(&clientCount)
		if err != nil {
			http.Error(w, "Ошибка проверки доступа компании", http.StatusInternalServerError)
			return
		}

		companies = append(companies, map[string]interface{}{
			"ID":                c.ID,
			"Name":              c.Name,
			"TrialUntil":        c.TrialUntil,
			"SubscriptionUntil": c.SubscriptionUntil,
			"IsActive":          c.IsActive,
			"LeadUserID":        c.LeadUserID,
			"CreatedAt":         c.CreatedAt,
			"HasAccess":         clientCount > 0,
		})
	}

	data := map[string]interface{}{
		"Title":     "Lead Dashboard",
		"User":      user,
		"Companies": companies,
	}

	renderTemplate(w, "lead_dashboard.html", data)
}

func leadCompanyAddHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := requireRole(w, r, "lead", "owner")
	if !ok {
		return
	}

	if r.Method == http.MethodPost {
		name := r.FormValue("name")
		if name == "" {
			data := map[string]interface{}{
				"Title": "Добавить компанию",
				"Error": "Введите название компании",
			}
			renderTemplate(w, "lead_company_add.html", data)
			return
		}

		_, err := db.Exec(`
			INSERT INTO companies (name, trial_until, subscription_until, is_active, lead_user_id)
			VALUES ($1, CURRENT_DATE + INTERVAL '7 days', CURRENT_DATE + INTERVAL '30 days', true, $2)
		`, name, user.ID)
		if err != nil {
			http.Error(w, "Ошибка создания компании", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/lead/dashboard", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	data := map[string]interface{}{
		"Title": "Добавить компанию",
	}

	renderTemplate(w, "lead_company_add.html", data)
}

func leadCompanyAccessHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := requireRole(w, r, "lead", "owner")
	if !ok {
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	companyID, err := strconv.Atoi(companyIDStr)
	if err != nil {
		http.Error(w, "Неверный ID компании", http.StatusBadRequest)
		return
	}

	var company Company
	err = db.QueryRow(`
		SELECT id, name,
		       COALESCE(TO_CHAR(trial_until, 'DD.MM.YYYY'), ''),
		       COALESCE(TO_CHAR(subscription_until, 'DD.MM.YYYY'), ''),
		       is_active,
		       COALESCE(lead_user_id, 0),
		       TO_CHAR(created_at, 'DD.MM.YYYY HH24:MI')
		FROM companies
		WHERE id = $1 AND lead_user_id = $2
	`, companyID, user.ID).Scan(
		&company.ID,
		&company.Name,
		&company.TrialUntil,
		&company.SubscriptionUntil,
		&company.IsActive,
		&company.LeadUserID,
		&company.CreatedAt,
	)
	if err != nil {
		http.Error(w, "Компания не найдена", http.StatusNotFound)
		return
	}

	var existingClient User
	err = db.QueryRow(`
		SELECT id, full_name, email, password_hash, role, COALESCE(company_id, 0),
		       TO_CHAR(created_at, 'DD.MM.YYYY HH24:MI')
		FROM users
		WHERE company_id = $1 AND role = 'client'
		ORDER BY id DESC
		LIMIT 1
	`, company.ID).Scan(
		&existingClient.ID,
		&existingClient.FullName,
		&existingClient.Email,
		&existingClient.PasswordHash,
		&existingClient.Role,
		&existingClient.CompanyID,
		&existingClient.CreatedAt,
	)

	hasAccess := err == nil

	if r.Method == http.MethodPost {
		if hasAccess {
			data := map[string]interface{}{
				"Title":          "Выдать доступ",
				"Error":          "Доступ уже был выдан для этой компании",
				"Company":        company,
				"ExistingClient": existingClient,
				"HasAccess":      true,
			}
			renderTemplate(w, "lead_company_access.html", data)
			return
		}
		fullName := r.FormValue("full_name")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if fullName == "" || email == "" || password == "" {
			data := map[string]interface{}{
				"Title":          "Выдать доступ",
				"Error":          "Заполните все поля",
				"Company":        company,
				"ExistingClient": existingClient,
				"HasAccess":      hasAccess,
			}
			renderTemplate(w, "lead_company_access.html", data)
			return
		}

		hashedPassword, err := hashPassword(password)
		if err != nil {
			http.Error(w, "Ошибка хеширования пароля", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec(`
			INSERT INTO users (full_name, email, password_hash, role, company_id)
			VALUES ($1, $2, $3, 'client', $4)
		`, fullName, email, hashedPassword, company.ID)
		if err != nil {
			data := map[string]interface{}{
				"Title":          "Выдать доступ",
				"Error":          "Не удалось создать доступ. Возможно, email уже занят",
				"Company":        company,
				"ExistingClient": existingClient,
				"HasAccess":      hasAccess,
			}
			renderTemplate(w, "lead_company_access.html", data)
			return
		}

		data := map[string]interface{}{
			"Title":           "Доступ создан",
			"Company":         company,
			"Success":         "Доступ клиенту успешно выдан",
			"CreatedEmail":    email,
			"CreatedPassword": password,
			"ExistingClient":  existingClient,
			"HasAccess":       hasAccess,
		}
		renderTemplate(w, "lead_company_access.html", data)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	data := map[string]interface{}{
		"Title":          "Выдать доступ",
		"Company":        company,
		"ExistingClient": existingClient,
		"HasAccess":      hasAccess,
	}

	renderTemplate(w, "lead_company_access.html", data)
}

func ownerDashboardHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := requireRole(w, r, "owner")
	if !ok {
		return
	}

	rows, err := db.Query(`
		SELECT c.id, c.name,
		       COALESCE(TO_CHAR(c.trial_until, 'DD.MM.YYYY'), ''),
		       COALESCE(TO_CHAR(c.subscription_until, 'DD.MM.YYYY'), ''),
		       c.is_active,
		       COALESCE(c.lead_user_id, 0),
		       TO_CHAR(c.created_at, 'DD.MM.YYYY HH24:MI'),
		       COALESCE(u.full_name, '')
		FROM companies c
		LEFT JOIN users u ON u.id = c.lead_user_id
		ORDER BY c.id DESC
	`)
	if err != nil {
		http.Error(w, "Ошибка загрузки компаний", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var companies []map[string]interface{}
	for rows.Next() {
		var c Company
		var leadName string
		err := rows.Scan(
			&c.ID,
			&c.Name,
			&c.TrialUntil,
			&c.SubscriptionUntil,
			&c.IsActive,
			&c.LeadUserID,
			&c.CreatedAt,
			&leadName,
		)
		if err != nil {
			http.Error(w, "Ошибка чтения компаний", http.StatusInternalServerError)
			return
		}

		var clientCount int
		err = db.QueryRow(`
			SELECT COUNT(*)
			FROM users
			WHERE company_id = $1 AND role = 'client'
		`, c.ID).Scan(&clientCount)
		if err != nil {
			http.Error(w, "Ошибка проверки доступа компании", http.StatusInternalServerError)
			return
		}

		companies = append(companies, map[string]interface{}{
			"ID":                c.ID,
			"Name":              c.Name,
			"TrialUntil":        c.TrialUntil,
			"SubscriptionUntil": c.SubscriptionUntil,
			"IsActive":          c.IsActive,
			"LeadUserID":        c.LeadUserID,
			"LeadName":          leadName,
			"CreatedAt":         c.CreatedAt,
			"HasAccess":         clientCount > 0,
		})
	}

	var leadsCount int
	err = db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'lead'`).Scan(&leadsCount)
	if err != nil {
		http.Error(w, "Ошибка загрузки lead-пользователей", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Title":      "Owner Dashboard",
		"User":       user,
		"Companies":  companies,
		"LeadsCount": leadsCount,
	}

	renderTemplate(w, "owner_dashboard.html", data)
}

func ownerLeadsHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireRole(w, r, "owner")
	if !ok {
		return
	}

	rows, err := db.Query(`
		SELECT u.id, u.full_name, u.email,
		       TO_CHAR(u.created_at, 'DD.MM.YYYY HH24:MI')
		FROM users u
		WHERE u.role = 'lead'
		ORDER BY u.id DESC
	`)
	if err != nil {
		http.Error(w, "Ошибка загрузки lead-пользователей", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var leads []map[string]interface{}
	for rows.Next() {
		var id int
		var fullName, email, createdAt string
		err := rows.Scan(&id, &fullName, &email, &createdAt)
		if err != nil {
			http.Error(w, "Ошибка чтения lead-пользователей", http.StatusInternalServerError)
			return
		}

		var companiesCount int
		err = db.QueryRow(`
			SELECT COUNT(*)
			FROM companies
			WHERE lead_user_id = $1
		`, id).Scan(&companiesCount)
		if err != nil {
			http.Error(w, "Ошибка подсчёта компаний lead-пользователя", http.StatusInternalServerError)
			return
		}

		var activeCompaniesCount int
		err = db.QueryRow(`
			SELECT COUNT(*)
			FROM companies
			WHERE lead_user_id = $1 AND is_active = true
		`, id).Scan(&activeCompaniesCount)
		if err != nil {
			http.Error(w, "Ошибка подсчёта активных компаний", http.StatusInternalServerError)
			return
		}

		var accessIssuedCount int
		err = db.QueryRow(`
			SELECT COUNT(*)
			FROM companies c
			WHERE c.lead_user_id = $1
			  AND EXISTS (
				SELECT 1
				FROM users u
				WHERE u.company_id = c.id AND u.role = 'client'
			  )
		`, id).Scan(&accessIssuedCount)
		if err != nil {
			http.Error(w, "Ошибка подсчёта выданных доступов", http.StatusInternalServerError)
			return
		}

		leads = append(leads, map[string]interface{}{
			"ID":                   id,
			"FullName":             fullName,
			"Email":                email,
			"CreatedAt":            createdAt,
			"CompaniesCount":       companiesCount,
			"ActiveCompaniesCount": activeCompaniesCount,
			"AccessIssuedCount":    accessIssuedCount,
		})
	}

	data := map[string]interface{}{
		"Title": "Lead'ы",
		"Leads": leads,
	}

	renderTemplate(w, "owner_leads.html", data)
}

func ownerLeadAddHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireRole(w, r, "owner")
	if !ok {
		return
	}

	if r.Method == http.MethodPost {
		fullName := r.FormValue("full_name")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if fullName == "" || email == "" || password == "" {
			data := map[string]interface{}{
				"Title": "Добавить lead",
				"Error": "Заполните все поля",
			}
			renderTemplate(w, "owner_lead_add.html", data)
			return
		}

		hashedPassword, err := hashPassword(password)
		if err != nil {
			http.Error(w, "Ошибка хеширования пароля", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec(`
			INSERT INTO users (full_name, email, password_hash, role, company_id)
			VALUES ($1, $2, $3, 'lead', NULL)
		`, fullName, email, hashedPassword)
		if err != nil {
			data := map[string]interface{}{
				"Title": "Добавить lead",
				"Error": "Не удалось создать lead. Возможно, email уже занят",
			}
			renderTemplate(w, "owner_lead_add.html", data)
			return
		}

		data := map[string]interface{}{
			"Title":           "Lead создан",
			"Success":         "Аккаунт lead успешно создан",
			"CreatedEmail":    email,
			"CreatedPassword": password,
		}
		renderTemplate(w, "owner_lead_add.html", data)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	data := map[string]interface{}{
		"Title": "Добавить lead",
	}

	renderTemplate(w, "owner_lead_add.html", data)
}

func ownerCompanyDetailHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireRole(w, r, "owner")
	if !ok {
		return
	}

	companyIDStr := r.URL.Query().Get("id")
	companyID, err := strconv.Atoi(companyIDStr)
	if err != nil {
		http.Error(w, "Неверный ID компании", http.StatusBadRequest)
		return
	}

	var company Company
	var leadName string
	err = db.QueryRow(`
		SELECT c.id, c.name,
		       COALESCE(TO_CHAR(c.trial_until, 'DD.MM.YYYY'), ''),
		       COALESCE(TO_CHAR(c.subscription_until, 'DD.MM.YYYY'), ''),
		       c.is_active,
		       COALESCE(c.lead_user_id, 0),
		       TO_CHAR(c.created_at, 'DD.MM.YYYY HH24:MI'),
		       COALESCE(u.full_name, '')
		FROM companies c
		LEFT JOIN users u ON u.id = c.lead_user_id
		WHERE c.id = $1
	`, companyID).Scan(
		&company.ID,
		&company.Name,
		&company.TrialUntil,
		&company.SubscriptionUntil,
		&company.IsActive,
		&company.LeadUserID,
		&company.CreatedAt,
		&leadName,
	)
	if err != nil {
		http.Error(w, "Компания не найдена", http.StatusNotFound)
		return
	}

	var clientUser User
	var hasClientAccess bool
	err = db.QueryRow(`
		SELECT id, full_name, email, password_hash, role, COALESCE(company_id, 0),
		       TO_CHAR(created_at, 'DD.MM.YYYY HH24:MI')
		FROM users
		WHERE company_id = $1 AND role = 'client'
		ORDER BY id DESC
		LIMIT 1
	`, company.ID).Scan(
		&clientUser.ID,
		&clientUser.FullName,
		&clientUser.Email,
		&clientUser.PasswordHash,
		&clientUser.Role,
		&clientUser.CompanyID,
		&clientUser.CreatedAt,
	)
	if err == nil {
		hasClientAccess = true
	}

	var clientsCount int
	err = db.QueryRow(`SELECT COUNT(*) FROM clients WHERE company_id = $1`, company.ID).Scan(&clientsCount)
	if err != nil {
		http.Error(w, "Ошибка подсчёта клиентов компании", http.StatusInternalServerError)
		return
	}

	var ordersCount int
	err = db.QueryRow(`SELECT COUNT(*) FROM orders WHERE company_id = $1`, company.ID).Scan(&ordersCount)
	if err != nil {
		http.Error(w, "Ошибка подсчёта заказов компании", http.StatusInternalServerError)
		return
	}

	var expensesCount int
	err = db.QueryRow(`SELECT COUNT(*) FROM expenses WHERE company_id = $1`, company.ID).Scan(&expensesCount)
	if err != nil {
		http.Error(w, "Ошибка подсчёта расходов компании", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Title":           "Компания",
		"Company":         company,
		"LeadName":        leadName,
		"HasClientAccess": hasClientAccess,
		"ClientUser":      clientUser,
		"ClientsCount":    clientsCount,
		"OrdersCount":     ordersCount,
		"ExpensesCount":   expensesCount,
	}

	renderTemplate(w, "owner_company_detail.html", data)
}

func ownerCompanyToggleHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireRole(w, r, "owner")
	if !ok {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	companyID, err := strconv.Atoi(companyIDStr)
	if err != nil {
		http.Error(w, "Неверный ID компании", http.StatusBadRequest)
		return
	}

	_, err = db.Exec(`
		UPDATE companies
		SET is_active = NOT is_active
		WHERE id = $1
	`, companyID)
	if err != nil {
		http.Error(w, "Ошибка изменения статуса компании", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/owner/dashboard", http.StatusSeeOther)
}

func ownerCompanyExtendHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireRole(w, r, "owner")
	if !ok {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	companyIDStr := r.URL.Query().Get("company_id")
	companyID, err := strconv.Atoi(companyIDStr)
	if err != nil {
		http.Error(w, "Неверный ID компании", http.StatusBadRequest)
		return
	}

	_, err = db.Exec(`
		UPDATE companies
		SET subscription_until = COALESCE(subscription_until, CURRENT_DATE) + INTERVAL '30 days',
		    is_active = true
		WHERE id = $1
	`, companyID)
	if err != nil {
		http.Error(w, "Ошибка продления подписки", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/owner/dashboard", http.StatusSeeOther)
}

func clientsHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireActiveClientAccess(w, r)
	if !ok {
		return
	}
	companyID := currentCompanyID(r)

	rows, err := db.Query(`
		SELECT id, company_id, name, phone, car_number, car_model
		FROM clients
		WHERE company_id = $1
		ORDER BY id DESC
	`, companyID)
	if err != nil {
		http.Error(w, "Ошибка загрузки клиентов", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var clients []Client

	for rows.Next() {
		var c Client
		err := rows.Scan(&c.ID, &c.CompanyID, &c.Name, &c.Phone, &c.CarNumber, &c.CarModel)
		if err != nil {
			http.Error(w, "Ошибка чтения клиентов", http.StatusInternalServerError)
			return
		}
		clients = append(clients, c)
	}

	data := map[string]interface{}{
		"Title":   "Клиенты",
		"Clients": clients,
	}

	renderTemplate(w, "clients.html", data)
}

func clientAddHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireActiveClientAccess(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		companyID := currentCompanyID(r)

		name := r.FormValue("name")
		phone := r.FormValue("phone")
		carNumber := r.FormValue("car_number")
		carModel := r.FormValue("car_model")

		_, err := db.Exec(`
			INSERT INTO clients (company_id, name, phone, car_number, car_model)
			VALUES ($1, $2, $3, $4, $5)
		`, companyID, name, phone, carNumber, carModel)
		if err != nil {
			http.Error(w, "Ошибка сохранения клиента", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/clients", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"Title": "Добавить клиента",
	}

	renderTemplate(w, "client_add.html", data)
}

func orderEditHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireActiveClientAccess(w, r)
	if !ok {
		return
	}
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID заказа", http.StatusBadRequest)
		return
	}
	companyID := currentCompanyID(r)

	if r.Method == http.MethodPost {
		clientID := r.FormValue("client_id")
		service := r.FormValue("service")
		price := r.FormValue("price")
		paymentType := r.FormValue("payment_type")
		status := r.FormValue("status")

		_, err := db.Exec(`
			UPDATE orders
			SET client_id = $1, service = $2, price = $3, payment_type = $4, status = $5
			WHERE id = $6 AND company_id = $7
		`, clientID, service, price, paymentType, status, id, companyID)
		if err != nil {
			http.Error(w, "Ошибка обновления заказа", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/orders", http.StatusSeeOther)
		return
	}

	var order struct {
		ID          int
		ClientID    int
		Service     string
		Price       float64
		PaymentType string
		Status      string
	}

	err = db.QueryRow(`
		SELECT id, client_id, service, price, payment_type, status
		FROM orders
		WHERE id = $1 AND company_id = $2
	`, id, companyID).Scan(&order.ID, &order.ClientID, &order.Service, &order.Price, &order.PaymentType, &order.Status)
	if err != nil {
		http.Error(w, "Заказ не найден", http.StatusNotFound)
		return
	}

	rows, err := db.Query(`SELECT id, name FROM clients WHERE company_id = $1 ORDER BY name`, companyID)
	if err != nil {
		http.Error(w, "Ошибка загрузки клиентов", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		var c Client
		err := rows.Scan(&c.ID, &c.Name)
		if err != nil {
			http.Error(w, "Ошибка чтения клиентов", http.StatusInternalServerError)
			return
		}
		clients = append(clients, c)
	}

	data := map[string]interface{}{
		"Title":   "Редактировать заказ",
		"Order":   order,
		"Clients": clients,
	}

	renderTemplate(w, "order_edit.html", data)
}

func orderDeleteHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireActiveClientAccess(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID заказа", http.StatusBadRequest)
		return
	}
	companyID := currentCompanyID(r)

	_, err = db.Exec(`DELETE FROM orders WHERE id = $1 AND company_id = $2`, id, companyID)
	if err != nil {
		http.Error(w, "Ошибка удаления заказа", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/orders", http.StatusSeeOther)
}

func ordersHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireActiveClientAccess(w, r)
	if !ok {
		return
	}
	companyID := currentCompanyID(r)

	rows, err := db.Query(`
		SELECT o.id, o.company_id, o.client_id, c.name, o.service, o.price, o.payment_type, o.status,
		       TO_CHAR(o.created_at, 'DD.MM.YYYY HH24:MI')
		FROM orders o
		LEFT JOIN clients c ON c.id = o.client_id AND c.company_id = o.company_id
		WHERE o.company_id = $1
		ORDER BY o.id DESC
	`, companyID)
	if err != nil {
		http.Error(w, "Ошибка загрузки заказов", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var orders []Order

	for rows.Next() {
		var o Order
		err := rows.Scan(
			&o.ID,
			&o.CompanyID,
			&o.ClientID,
			&o.ClientName,
			&o.Service,
			&o.Price,
			&o.PaymentType,
			&o.Status,
			&o.CreatedAt,
		)
		if err != nil {
			http.Error(w, "Ошибка чтения заказов", http.StatusInternalServerError)
			return
		}
		orders = append(orders, o)
	}

	data := map[string]interface{}{
		"Title":  "Заказы",
		"Orders": orders,
	}

	renderTemplate(w, "orders.html", data)
}

func orderAddHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireActiveClientAccess(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		companyID := currentCompanyID(r)

		clientID := r.FormValue("client_id")
		service := r.FormValue("service")
		price := r.FormValue("price")
		paymentType := r.FormValue("payment_type")
		status := r.FormValue("status")

		_, err := db.Exec(`
			INSERT INTO orders (company_id, client_id, service, price, payment_type, status)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, companyID, clientID, service, price, paymentType, status)
		if err != nil {
			http.Error(w, "Ошибка сохранения", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/orders", http.StatusSeeOther)
		return
	}

	companyID := currentCompanyID(r)
	rows, err := db.Query(`SELECT id, name FROM clients WHERE company_id = $1 ORDER BY name`, companyID)
	if err != nil {
		http.Error(w, "Ошибка загрузки клиентов", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var clients []Client

	for rows.Next() {
		var c Client
		err := rows.Scan(&c.ID, &c.Name)
		if err != nil {
			http.Error(w, "Ошибка чтения клиентов", http.StatusInternalServerError)
			return
		}
		clients = append(clients, c)
	}

	data := map[string]interface{}{
		"Title":   "Добавить заказ",
		"Clients": clients,
	}

	renderTemplate(w, "order_add.html", data)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireActiveClientAccess(w, r)
	if !ok {
		return
	}
	companyID := currentCompanyID(r)

	var totalRevenue float64
	var ordersCount int
	var totalExpenses float64

	err := db.QueryRow(`SELECT COALESCE(SUM(price), 0) FROM orders WHERE company_id = $1`, companyID).Scan(&totalRevenue)
	if err != nil {
		http.Error(w, "Ошибка загрузки выручки", http.StatusInternalServerError)
		return
	}

	err = db.QueryRow(`SELECT COUNT(*) FROM orders WHERE company_id = $1`, companyID).Scan(&ordersCount)
	if err != nil {
		http.Error(w, "Ошибка загрузки количества заказов", http.StatusInternalServerError)
		return
	}

	err = db.QueryRow(`SELECT COALESCE(SUM(amount), 0) FROM expenses WHERE company_id = $1`, companyID).Scan(&totalExpenses)
	if err != nil {
		http.Error(w, "Ошибка загрузки расходов", http.StatusInternalServerError)
		return
	}

	profit := totalRevenue - totalExpenses

	data := map[string]interface{}{
		"Title":         "Главная",
		"TotalRevenue":  totalRevenue,
		"OrdersCount":   ordersCount,
		"TotalExpenses": totalExpenses,
		"Profit":        profit,
	}

	renderTemplate(w, "dashboard.html", data)
}

func expensesHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireActiveClientAccess(w, r)
	if !ok {
		return
	}
	companyID := currentCompanyID(r)

	rows, err := db.Query(`
		SELECT id, company_id, name, amount,
		       TO_CHAR(created_at, 'DD.MM.YYYY HH24:MI')
		FROM expenses
		WHERE company_id = $1
		ORDER BY id DESC
	`, companyID)
	if err != nil {
		http.Error(w, "Ошибка загрузки расходов", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var expenses []Expense

	for rows.Next() {
		var e Expense
		err := rows.Scan(&e.ID, &e.CompanyID, &e.Name, &e.Amount, &e.CreatedAt)
		if err != nil {
			http.Error(w, "Ошибка чтения расходов", http.StatusInternalServerError)
			return
		}
		expenses = append(expenses, e)
	}

	data := map[string]interface{}{
		"Title":    "Расходы",
		"Expenses": expenses,
	}

	renderTemplate(w, "expenses.html", data)
}

func expenseAddHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireActiveClientAccess(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		companyID := currentCompanyID(r)

		name := r.FormValue("name")
		amount := r.FormValue("amount")

		_, err := db.Exec(`
			INSERT INTO expenses (company_id, name, amount)
			VALUES ($1, $2, $3)
		`, companyID, name, amount)
		if err != nil {
			http.Error(w, "Ошибка сохранения", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/expenses", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"Title": "Добавить расход",
	}

	renderTemplate(w, "expense_add.html", data)
}

func expenseEditHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireActiveClientAccess(w, r)
	if !ok {
		return
	}
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID расхода", http.StatusBadRequest)
		return
	}
	companyID := currentCompanyID(r)

	if r.Method == http.MethodPost {
		name := r.FormValue("name")
		amount := r.FormValue("amount")

		_, err := db.Exec(`
			UPDATE expenses
			SET name = $1, amount = $2
			WHERE id = $3 AND company_id = $4
		`, name, amount, id, companyID)
		if err != nil {
			http.Error(w, "Ошибка обновления расхода", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/expenses", http.StatusSeeOther)
		return
	}

	var expense Expense
	err = db.QueryRow(`
		SELECT id, company_id, name, amount,
		       TO_CHAR(created_at, 'DD.MM.YYYY HH24:MI')
		FROM expenses
		WHERE id = $1 AND company_id = $2
	`, id, companyID).Scan(&expense.ID, &expense.CompanyID, &expense.Name, &expense.Amount, &expense.CreatedAt)
	if err != nil {
		http.Error(w, "Расход не найден", http.StatusNotFound)
		return
	}

	data := map[string]interface{}{
		"Title":   "Редактировать расход",
		"Expense": expense,
	}

	renderTemplate(w, "expense_edit.html", data)
}

func expenseDeleteHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireActiveClientAccess(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID расхода", http.StatusBadRequest)
		return
	}
	companyID := currentCompanyID(r)

	_, err = db.Exec(`DELETE FROM expenses WHERE id = $1 AND company_id = $2`, id, companyID)
	if err != nil {
		http.Error(w, "Ошибка удаления расхода", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/expenses", http.StatusSeeOther)
}

func clientDetailHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireActiveClientAccess(w, r)
	if !ok {
		return
	}
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID клиента", http.StatusBadRequest)
		return
	}
	companyID := currentCompanyID(r)

	var client Client
	err = db.QueryRow(`
		SELECT id, company_id, name, phone, car_number, car_model
		FROM clients
		WHERE id = $1 AND company_id = $2
	`, id, companyID).Scan(&client.ID, &client.CompanyID, &client.Name, &client.Phone, &client.CarNumber, &client.CarModel)
	if err != nil {
		http.Error(w, "Клиент не найден", http.StatusNotFound)
		return
	}

	rows, err := db.Query(`
		SELECT o.id, o.company_id, o.client_id, c.name, o.service, o.price, o.payment_type, o.status,
		       TO_CHAR(o.created_at, 'DD.MM.YYYY HH24:MI')
		FROM orders o
		LEFT JOIN clients c ON c.id = o.client_id AND c.company_id = o.company_id
		WHERE o.client_id = $1 AND o.company_id = $2
		ORDER BY o.id DESC
	`, id, companyID)
	if err != nil {
		http.Error(w, "Ошибка загрузки заказов клиента", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var orders []Order
	var totalSpent float64

	for rows.Next() {
		var o Order
		err := rows.Scan(
			&o.ID,
			&o.CompanyID,
			&o.ClientID,
			&o.ClientName,
			&o.Service,
			&o.Price,
			&o.PaymentType,
			&o.Status,
			&o.CreatedAt,
		)
		if err != nil {
			http.Error(w, "Ошибка чтения заказов клиента", http.StatusInternalServerError)
			return
		}
		totalSpent += o.Price
		orders = append(orders, o)
	}

	data := map[string]interface{}{
		"Title":      "История клиента",
		"Client":     client,
		"Orders":     orders,
		"TotalSpent": totalSpent,
	}

	renderTemplate(w, "client_detail.html", data)
}

func clientEditHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireActiveClientAccess(w, r)
	if !ok {
		return
	}
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID клиента", http.StatusBadRequest)
		return
	}
	companyID := currentCompanyID(r)

	if r.Method == http.MethodPost {
		name := r.FormValue("name")
		phone := r.FormValue("phone")
		carNumber := r.FormValue("car_number")
		carModel := r.FormValue("car_model")

		_, err := db.Exec(`
			UPDATE clients
			SET name = $1, phone = $2, car_number = $3, car_model = $4
			WHERE id = $5 AND company_id = $6
		`, name, phone, carNumber, carModel, id, companyID)
		if err != nil {
			http.Error(w, "Ошибка обновления клиента", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/clients", http.StatusSeeOther)
		return
	}

	var client Client
	err = db.QueryRow(`
		SELECT id, company_id, name, phone, car_number, car_model
		FROM clients
		WHERE id = $1 AND company_id = $2
	`, id, companyID).Scan(&client.ID, &client.CompanyID, &client.Name, &client.Phone, &client.CarNumber, &client.CarModel)
	if err != nil {
		http.Error(w, "Клиент не найден", http.StatusNotFound)
		return
	}

	data := map[string]interface{}{
		"Title":  "Редактировать клиента",
		"Client": client,
	}

	renderTemplate(w, "client_edit.html", data)
}

func clientDeleteHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireActiveClientAccess(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID клиента", http.StatusBadRequest)
		return
	}
	companyID := currentCompanyID(r)

	_, err = db.Exec(`DELETE FROM clients WHERE id = $1 AND company_id = $2`, id, companyID)
	if err != nil {
		http.Error(w, "Ошибка удаления клиента", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/clients", http.StatusSeeOther)
}
