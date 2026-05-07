#!/bin/bash

echo "Starting PassVault setup..."

# Check if python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "python3 could not be found. Please install it first."
    exit 1
fi

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install requirements
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Setup the database
echo "Initializing database..."
python run_init_db.py

echo "Setup complete. To run the app, use:"
echo "source venv/bin/activate"
echo "python app.py"
