.PHONY: help build up down logs ps test clean

help:
	@echo "Auth API - Development Commands"
	@echo ""
	@echo "  make build      Build Docker image"
	@echo "  make up        Start services with docker-compose"
	@echo "  make down      Stop services"
	@echo "  make logs      Tail logs"
	@echo "  make ps        Show running containers"
	@echo "  make test      Run tests"
	@echo "  make clean     Remove containers and volumes"

build:
	docker build -t auth-api:latest .

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

ps:
	docker compose ps

test:
	docker compose exec auth-api cargo test

clean:
	docker compose down -v --remove-orphans
