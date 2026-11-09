# Deployment Guide: Red Hat OpenShift & Developer Sandbox

This guide provides clear, step-by-step instructions to deploy the **Secure Task Management System** to the **Red Hat Developer Sandbox** using OpenShift.

---

## 1. Architecture Overview on OpenShift

```text
[ Browser / Client ]
         │ (HTTPS / TLS Edge Termination)
         ▼
[ OpenShift Route ] ──── Public Domain (e.g., https://secure-task-manager-<user>-dev.apps.sandbox...)
         │ (HTTP port 8080)
         ▼
[ Service: secure-task-manager:8080 ]
         │
         ▼
[ Pod: secure-task-manager ] ── (Red Hat UBI 9 PHP 8.2 Runtime, UID 1001 / GID 0)
         │
         │ (Internal TCP port 3306, authenticated via Secret)
         ▼
[ Service: mysql:3306 ]
         │
         ▼
[ Pod: mysql (RHEL 8 MySQL 8.0) ]
         │
         ▼
[ PersistentVolumeClaim: mysql-data (1Gi Storage) ]
```

---

## 2. Technology Stack & Runtime Compatibility

| Component | Local XAMPP | Red Hat OpenShift Sandbox | Compatibility Details |
| :--- | :--- | :--- | :--- |
| **Base OS** | Windows 10/11 | Red Hat Enterprise Linux 9 (UBI 9) | Native enterprise Linux container |
| **PHP Runtime** | PHP 8.2 (Windows CLI/Apache) | PHP 8.2 (Red Hat UBI 9) | Modules: `pdo`, `pdo_mysql`, `mbstring`, `json`, `session` |
| **Web Server** | Apache (Port 80) | Apache (Port **8080**) | OpenShift non-root compliance |
| **Database** | MySQL (Port 3306) | MySQL 8.0 via `registry.redhat.io/rhel8/mysql-80` | Internal Service DNS `mysql:3306` |
| **File Permissions** | Windows ACL | Arbitrary Random UID, GID 0 (`root`) | Group permissions `chmod -R g=u` configured |
| **SSL / HTTPS** | None / Self-signed | OpenShift Edge Route | Automated valid SSL certificates |

---

## 3. Environment Variables & Secrets Reference

All database credentials are managed via the OpenShift Secret [`openshift/secret.yaml`](openshift/secret.yaml) to ensure zero hardcoded secrets in production:

| Variable | Secret Key | Default in Manifest | Description |
| :--- | :--- | :--- | :--- |
| `DB_HOST` | `DB_HOST` | `mysql` | Internal OpenShift DNS name for the MySQL Service |
| `DB_PORT` | `DB_PORT` | `3306` | Port of the internal MySQL database service |
| `DB_NAME` | `DB_NAME` | `secure_task_manager` | Database schema name |
| `DB_USER` | `DB_USER` | `taskuser` | Application MySQL database user |
| `DB_PASS` | `DB_PASS` | `SecureTaskUserPass2026!` | Application MySQL user password |
| `MYSQL_ROOT_PASSWORD` | `MYSQL_ROOT_PASSWORD` | `RootAdminPassword2026!` | MySQL root administrative password |

---

## 4. Deployment Method A: OpenShift Web Console (Beginner Friendly / GUI)

If you prefer using your web browser without installing terminal tools:

### Step 1: Log in to Red Hat Developer Sandbox
1. Go to [developers.redhat.com/developer-sandbox](https://developers.redhat.com/developer-sandbox).
2. Click **Start using your sandbox**.
3. In the OpenShift Web Console, switch to the **Developer** perspective (top-left dropdown).
4. Verify you are in your active project namespace (e.g., `username-dev`).

### Step 2: Deploy MySQL Database
1. Click **+Add** in the left sidebar menu.
2. Under **Developer Catalog**, click **Database**, then choose **MySQL**.
3. Click **Instantiate Template**:
   - **Database Service Name:** `mysql`
   - **MySQL Connection Username:** `taskuser`
   - **MySQL Connection Password:** `SecureTaskUserPass2026!`
   - **MySQL Root Password:** `RootAdminPassword2026!`
   - **Database Name:** `secure_task_manager`
4. Click **Create**. OpenShift will provision the MySQL pod and internal service `mysql:3306`.

### Step 3: Deploy the PHP Application from GitHub
1. Click **+Add** again.
2. Select **From Git**.
3. Paste your public GitHub repository URL:
   ```text
   https://github.com/<your-username>/secure-task-manager.git
   ```
4. OpenShift will automatically detect the **Dockerfile** or select **PHP 8.2 Builder Image**.
   - If prompted for builder image, select **PHP**, version **8.2-ubi9**.
5. Under **General**:
   - **Application Name:** `secure-task-management-system`
   - **Name:** `secure-task-manager`
6. Scroll down to **Deployment**:
   - Click **Environment Variables** and add:
     - `DB_HOST` = `mysql`
     - `DB_PORT` = `3306`
     - `DB_NAME` = `secure_task_manager`
     - `DB_USER` = `taskuser`
     - `DB_PASS` = `SecureTaskUserPass2026!`
7. Under **Routing**:
   - Ensure **Create a route to the Application** is checked.
   - Target Port: **8080 (TCP)**.
   - Check **Secure Route** -> TLS Termination: **Edge**, Insecure Traffic: **Redirect**.
8. Click **Create**!

---

## 5. Deployment Method B: OpenShift CLI (`oc`) (Automated / Infrastructure-as-Code)

If you have the `oc` command line client installed:

### Step 1: Log in via CLI
1. In the OpenShift Web Console, click your username in the top-right corner.
2. Click **Copy login command**, then click **Display Token**.
3. Copy the `oc login` command and run it in your terminal:
   ```bash
   oc login --token=sha256~XXXXX --server=https://api.sandbox-m2.ll9k.p1.openshiftapps.com:6443
   ```
4. Verify your current namespace:
   ```bash
   oc project
   ```

### Step 2: Apply the OpenShift Manifests
From your project root directory, apply all manifests in one command:
```bash
oc apply -k openshift/
```
*This automatically creates:*
- Secret `secure-task-secrets`
- PersistentVolumeClaim `mysql-data`
- Deployment & Service `mysql`
- ImageStream & BuildConfig `secure-task-manager`
- Deployment & Service `secure-task-manager`
- Edge HTTPS Route `secure-task-manager`

### Step 3: Build the Application Container
Trigger the build using your local source directory:
```bash
oc start-build secure-task-manager --from-dir=. --follow
```
OpenShift will build the container image using the `Dockerfile` and push it to the internal cluster registry.

---

## 6. Initializing the Database in OpenShift

Once both pods are running:

### Option 1 (One-Click Browser Setup):
Open your application's public route in the browser and append `/setup_database.php`:
```
https://secure-task-manager-<namespace>.apps.sandbox.../setup_database.php
```
The script connects to the internal `mysql:3306` service and automatically provisions all tables (`users`, `tasks`, `audit_logs`) and demo seed data!

### Option 2 (Via `oc exec` CLI):
```bash
# Get the MySQL pod name
MYSQL_POD=$(oc get pods -l tier=database -o jsonpath="{.items[0].metadata.name}")

# Import database.sql directly into the running MySQL container
oc exec -i $MYSQL_POD -- mysql -u root -pRootAdminPassword2026! secure_task_manager < database/database.sql
```

---

## 7. Verification & Troubleshooting

Check overall cluster status:
```bash
oc status
```

Check running pods:
```bash
oc get pods
```
*(Both `mysql-...` and `secure-task-manager-...` should show status `Running` and readiness `1/1`)*.

View real-time application logs:
```bash
oc logs -f deployment/secure-task-manager
```

Get your live public HTTPS URL:
```bash
oc get route secure-task-manager
```
