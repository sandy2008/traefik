package main

import (
	"fmt"
	"log"
	"net/http"
)

func handleHome(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")

	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>Protected Application</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .content { margin: 20px 0; }
        .user-info { background: #e8f5e9; padding: 10px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Protected Application</h1>
        <p>This application is protected by Active Directory authentication middleware</p>
    </div>
    
    <div class="content">
        <div class="user-info">
            <strong>Authenticated User:</strong> %s
        </div>
        
        <h2>Request Headers</h2>
        <ul>`, userID)

	for name, values := range r.Header {
		for _, value := range values {
			fmt.Fprintf(w, "<li><strong>%s:</strong> %s</li>\n", name, value)
		}
	}

	fmt.Fprintf(w, `
        </ul>
        
        <h2>Available Actions</h2>
        <ul>
            <li><a href="/read">Read Data</a> (requires read permission)</li>
            <li><a href="/write">Write Data</a> (requires write permission)</li>
            <li><a href="/admin">Admin Panel</a> (requires admin permission)</li>
        </ul>
    </div>
</body>
</html>`)
}

func handleRead(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Read Data</title></head>
<body>
    <h1>Read Data</h1>
    <p>User <strong>%s</strong> is reading data.</p>
    <p>This action requires "read" permission.</p>
    <p><a href="/">Back to Home</a></p>
</body>
</html>`, userID)
}

func handleWrite(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Write Data</title></head>
<body>
    <h1>Write Data</h1>
    <p>User <strong>%s</strong> is writing data.</p>
    <p>This action requires "write" permission.</p>
    <p><a href="/">Back to Home</a></p>
</body>
</html>`, userID)
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
    <h1>Admin Panel</h1>
    <p>User <strong>%s</strong> is accessing admin panel.</p>
    <p>This action requires "admin" permission.</p>
    <p><a href="/">Back to Home</a></p>
</body>
</html>`, userID)
}

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/read", handleRead)
	http.HandleFunc("/write", handleWrite)
	http.HandleFunc("/admin", handleAdmin)

	fmt.Println("Test application starting on :8082")
	fmt.Println("This app expects to receive X-User-ID header from Traefik")

	log.Fatal(http.ListenAndServe(":8082", nil))
}
