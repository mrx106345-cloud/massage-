.PHONY: install dev build typecheck lint format test clean

install:
	npm install

dev:
	npm run dev

build:
	npm run build

typecheck:
	npm run typecheck

lint:
	npm run lint

format:
	npm run format:write

format-check:
	npm run format:check

test:
	npm run test

clean:
	npm run clean || rm -rf dist
	@if [ -d android/app/build ]; then rm -rf android/app/build; fi
	@if [ -d release ]; then rm -rf release; fi
