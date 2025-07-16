# 🐳 SecurityWatch Pro - Docker Deployment Guide

## 🚀 Quick Start

### **1. One-Command Deployment**
```bash
# Clone and deploy in one command
git clone https://github.com/ahmganbit/SecuriWatch.git
cd SecuriWatch
./docker-deploy.sh deploy
```

### **2. Access the Dashboard**
- **Web Dashboard:** http://localhost:5000
- **API Endpoint:** http://localhost:5000/api/stats

---

## 📋 Prerequisites

- **Docker** 20.10+ installed
- **Docker Compose** 1.29+ installed
- **4GB RAM** minimum (8GB recommended)
- **10GB disk space** for logs and data

### **Install Docker (if needed)**
```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

---

## 🎯 Deployment Options

### **Option 1: Development Mode (Default)**
```bash
./docker-deploy.sh deploy
```
**Features:**
- Web dashboard on port 5000
- Background monitoring service
- SQLite database
- Local file storage

### **Option 2: Production Mode**
```bash
./docker-deploy.sh production
```
**Features:**
- Nginx reverse proxy with SSL
- PostgreSQL database
- Redis caching
- Auto-scaling capabilities
- Production security headers

### **Option 3: Manual Docker Compose**
```bash
# Development
docker-compose up -d

# Production with all services
docker-compose --profile production up -d
```

---

## 🔧 Configuration

### **Environment Variables**
Create `.env` file for custom configuration:
```bash
# Database
POSTGRES_PASSWORD=your_secure_password

# Security
SECRET_KEY=your_secret_key_here

# Monitoring
CHECK_INTERVAL=30
ALERT_FREQUENCY=15

# Email (optional)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

### **Volume Mounts**
```yaml
volumes:
  - ./data:/app/data          # Database and config
  - ./logs:/app/logs          # Application logs
  - ./reports:/app/reports    # Generated reports
  - /var/log:/var/log:ro      # Host system logs (read-only)
```

---

## 📊 Service Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Nginx Proxy   │    │  Web Dashboard  │    │ Background      │
│   (Port 80/443) │────│   (Port 5000)   │    │ Monitor Service │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐              │
         └──────────────│   PostgreSQL    │──────────────┘
                        │   (Production)  │
                        └─────────────────┘
                                 │
                        ┌─────────────────┐
                        │     Redis       │
                        │   (Caching)     │
                        └─────────────────┘
```

---

## 🛠️ Management Commands

### **Deployment Commands**
```bash
./docker-deploy.sh deploy          # Deploy development mode
./docker-deploy.sh production      # Deploy production mode
./docker-deploy.sh status          # Check deployment status
./docker-deploy.sh logs            # View application logs
./docker-deploy.sh stop            # Stop all services
./docker-deploy.sh restart         # Restart all services
./docker-deploy.sh cleanup         # Remove all containers and data
```

### **Docker Compose Commands**
```bash
# View running services
docker-compose ps

# View logs
docker-compose logs -f securitywatch-web
docker-compose logs -f securitywatch-monitor

# Scale web service
docker-compose up -d --scale securitywatch-web=3

# Update services
docker-compose pull
docker-compose up -d
```

---

## 🔍 Monitoring & Health Checks

### **Health Check Endpoints**
- **Web Service:** `curl http://localhost:5000/api/stats`
- **Container Health:** `docker-compose ps`

### **Log Locations**
```bash
# Application logs
docker-compose logs securitywatch-web
docker-compose logs securitywatch-monitor

# Nginx logs (production)
docker-compose logs nginx

# Database logs (production)
docker-compose logs postgres
```

### **Performance Monitoring**
```bash
# Resource usage
docker stats

# Container inspection
docker inspect securitywatch-web
```

---

## 🔒 Security Configuration

### **SSL/TLS Setup (Production)**
1. **Generate SSL Certificate:**
```bash
# Self-signed (development)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem

# Let's Encrypt (production)
certbot certonly --standalone -d yourdomain.com
cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem nginx/ssl/cert.pem
cp /etc/letsencrypt/live/yourdomain.com/privkey.pem nginx/ssl/key.pem
```

2. **Update Nginx Configuration:**
```bash
# Edit nginx/nginx.conf
# Update server_name to your domain
```

### **Firewall Configuration**
```bash
# Allow HTTP/HTTPS
sudo ufw allow 80
sudo ufw allow 443

# Allow SSH (if needed)
sudo ufw allow 22

# Enable firewall
sudo ufw enable
```

---

## 📈 Scaling & Performance

### **Horizontal Scaling**
```bash
# Scale web service
docker-compose up -d --scale securitywatch-web=3

# Load balancer will distribute traffic automatically
```

### **Resource Limits**
```yaml
# In docker-compose.yml
services:
  securitywatch-web:
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
```

### **Performance Tuning**
```bash
# Increase shared memory for PostgreSQL
echo 'kernel.shmmax = 268435456' >> /etc/sysctl.conf

# Optimize Docker daemon
echo '{"log-driver": "json-file", "log-opts": {"max-size": "10m", "max-file": "3"}}' > /etc/docker/daemon.json
```

---

## 🔄 Backup & Recovery

### **Database Backup**
```bash
# PostgreSQL backup
docker-compose exec postgres pg_dump -U securitywatch securitywatch > backup.sql

# SQLite backup (development)
cp data/security.db backup/security_$(date +%Y%m%d).db
```

### **Full System Backup**
```bash
# Backup all data
tar -czf securitywatch_backup_$(date +%Y%m%d).tar.gz data/ logs/ reports/
```

### **Restore from Backup**
```bash
# Stop services
docker-compose down

# Restore data
tar -xzf securitywatch_backup_20250116.tar.gz

# Restart services
docker-compose up -d
```

---

## 🐛 Troubleshooting

### **Common Issues**

1. **Port Already in Use**
```bash
# Check what's using port 5000
sudo lsof -i :5000

# Kill process or change port in docker-compose.yml
```

2. **Permission Denied**
```bash
# Fix file permissions
sudo chown -R $USER:$USER data/ logs/ reports/
chmod 755 data/ logs/ reports/
```

3. **Container Won't Start**
```bash
# Check logs
docker-compose logs securitywatch-web

# Rebuild image
docker-compose build --no-cache
```

4. **Database Connection Issues**
```bash
# Check PostgreSQL status
docker-compose exec postgres pg_isready

# Reset database
docker-compose down -v
docker-compose up -d
```

### **Debug Mode**
```bash
# Run in debug mode
docker-compose -f docker-compose.yml -f docker-compose.debug.yml up
```

---

## 🚀 Production Deployment Checklist

- [ ] SSL certificates configured
- [ ] Domain name pointed to server
- [ ] Firewall rules configured
- [ ] Database passwords changed
- [ ] Backup strategy implemented
- [ ] Monitoring alerts configured
- [ ] Log rotation configured
- [ ] Resource limits set
- [ ] Health checks working
- [ ] Load testing completed

---

## 📞 Support

- **Documentation:** [GitHub Wiki](https://github.com/ahmganbit/SecuriWatch/wiki)
- **Issues:** [GitHub Issues](https://github.com/ahmganbit/SecuriWatch/issues)
- **Email:** support@sysadmintoolspro.com

---

**🛡️ SecurityWatch Pro - Professional Security Monitoring in Docker**
