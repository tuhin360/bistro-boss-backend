# 🍽️ Bistro Boss Restaurant - Backend API

![Node.js](https://img.shields.io/badge/Node.js-18.x-green)
![Express](https://img.shields.io/badge/Express-5.x-lightgrey)
![MongoDB](https://img.shields.io/badge/MongoDB-6.x-green)
![Stripe](https://img.shields.io/badge/Stripe-18.x-blue)

**A complete backend solution** for Bistro Boss Restaurant's management system, handling everything from menu management to payment processing.

🔗 [Live Frontend Demo](https://bistro-boss-97f52.web.app/) 

## 🌟 Key Features

### 🛒 Order Management
- Complete food ordering workflow
- Cart functionality with persistent storage
- Order history tracking

### 💳 Payment System
- Secure Stripe integration
- Payment intent creation
- Transaction recording

### 🔐 Authentication
- JWT-based authentication
- Role-based access control
- Secure password handling

### 📊 Admin Dashboard
- Comprehensive statistics
- Sales analytics by category
- User management

## 🚀 Getting Started

### Prerequisites
- Node.js 16+
- MongoDB Atlas account
- Stripe account
- PNPM (optional)

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/bistro-boss-backend.git

# Navigate to project directory
cd bistro-boss-backend

# Install dependencies
pnpm install

# Set up environment variables
cp .env.example .env
