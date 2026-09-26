# ShadowTrap - synthetic attack generator (for LOCAL demo/testing ONLY).
# Run the web app first:  python -m app.webapp
import time
import requests

BASE = "http://127.0.0.1:5000"
KEY = "SHADOW-7F92-4C1A-B8E3"

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (compatible; AttackerBot/1.0)"


def show(title, r):
    print("\n[ATTACKER] " + title + " -> HTTP " + str(r.status_code))
    print(r.text[:200].replace("\n", " "))


print("=== Stage 1: Reconnaissance ===")
show("GET /robots.txt", s.get(BASE + "/robots.txt"))
show("GET /admin-backup", s.get(BASE + "/admin-backup"))
time.sleep(1)

print("\n=== Stage 2: Credential Probing ===")
show("GET /admin-backup/login", s.get(BASE + "/admin-backup/login"))
show("POST /admin-backup/login (admin/password123)",
     s.post(BASE + "/admin-backup/login",
            data={"username": "admin", "password": "password123"}))
time.sleep(1)

print("\n=== Stage 3: Honeytoken Interaction ===")
show("GET /api/v1/users?key=SHADOW-...",
     s.get(BASE + "/api/v1/users", params={"key": KEY}))
time.sleep(1)

print("\n=== Stage 4: Sensitive Resource Probing ===")
for f in ["/database_backup.sql", "/customer_records.csv",
          "/admin_notes.txt"]:
    show("GET " + f, s.get(BASE + f))

print("\n[+] Attack simulation finished.")
print("[+] Open the defender dashboard to see the reconstructed sequence:")
print("    streamlit run app/dashboard.py")
