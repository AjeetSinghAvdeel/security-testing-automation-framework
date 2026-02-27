"""Backend Configuration"""

import os
from datetime import timedelta

class Config:
    """Base configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    JWT_SECRET = os.getenv('JWT_SECRET', 'dev-jwt-secret')
    
    # Database
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_DB = os.getenv('MONGO_DB', 'security_framework')
    
    # Blockchain
    GANACHE_URL = os.getenv('GANACHE_URL', 'http://localhost:7545')
    CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS', '')
    
    # SIEM
    ELASTICSEARCH_HOST = os.getenv('ELASTICSEARCH_HOST', 'localhost')
    ELASTICSEARCH_PORT = int(os.getenv('ELASTICSEARCH_PORT', 9200))
    
    # IoT
    MQTT_BROKER = os.getenv('MQTT_BROKER', 'localhost')
    MQTT_PORT = int(os.getenv('MQTT_PORT', 1883))
    
    # Security
    MAX_PAYLOAD_SIZE = int(os.getenv('MAX_PAYLOAD_SIZE', 1024))
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', 30))
    
    # Flags
    TEST_MODE = os.getenv('TEST_MODE', 'True').lower() == 'true'
    SAFE_MODE = os.getenv('SAFE_MODE', 'True').lower() == 'true'
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    
    # Features
    BLOCKCHAIN_ENABLED = os.getenv('BLOCKCHAIN_ENABLED', 'True').lower() == 'true'
    SIEM_INTEGRATION = os.getenv('SIEM_INTEGRATION', 'True').lower() == 'true'
    
    # JWT
    JWT_ALGORITHM = 'HS256'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    MONGO_DB = 'security_framework_test'

# Export configuration based on environment
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
