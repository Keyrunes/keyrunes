## [unreleased]

### 🚀 Features

- *(test)* Add Goose stress test infrastructure with 3 scenarios

### 🐛 Bug Fixes

- Fix delete users

### ⚙️ Miscellaneous Tasks

- *(ci)* Fix audit exemptions and code formatting
- Update dependencies and resolve 5 security advisories
- *(tests)* Remove hurl files from cargo tests directory
## [0.2.0.1] - 2026-02-27

### 🐛 Bug Fixes

- Typo error
- Typing error in text - pull request #34 from Yummy-Yums/main
- *(services)* Implement auto-healing for default groups and fix broken tests
- Problem with register new users with default groups

### 💼 Other

- Add config for build in dokku
- Add config for build in dokku

### 🧪 Testing

- Reenable migrations and change test for async

### ⚙️ Miscellaneous Tasks

- Add changelogs
- Fix app.json for dokku
## [0.2.0] - 2026-01-02

### 🚀 Features

- Add multi tenant support and organizations
- Add multi tenant with support to multi schemas in database, refactor api, cli and views for this format

### 💼 Other

- Add sqlx cache for ci
- Prepare queries offline to docker image and fix tests

### ⚙️ Miscellaneous Tasks

- Update changelog
- Add changelogs
## [0.1.1] - 2025-11-29

### 🚀 Features

- Add check groups in api and cli

### 🐛 Bug Fixes

- Change jsonwebtoken to josekit and remove sqlx-mysql and rsa

### 💼 Other

- Update libraries
- Add ignore in cargo audit false positive

### ⚙️ Miscellaneous Tasks

- Update changelog
## [0.1.0] - 2025-11-27

### 🚀 Features

- Merge main repository
- Add dotenvy cargo to read the environment variables
- Add table reset password, groups and policies
- Add forgot password, start new login and groups and polices features
- Add tests
- *(user)* Add admin endpoint for user registration with groups
- Improve logs and tracings and add new pages
- Cli tool for password recovery
- Add forgot password view route

### 🐛 Bug Fixes

- Fix error in register with first login
- Register router for signup and login
- Removed redundant routes
- Register and login nav links removed after login
- Provide database_url
- Redirect to dashboard properly
- Adding default run
- Saved tokens in db and added settings table
- Resolved comments
- Fix merge

### 💼 Other

- Initial commit
- Create README.md

create readme
- Update docker-compose.yml
- Merge pull request #10 from jdssl/chore/development-setup

chore/development setup
- Pull from upstream
- Add new route to tracing
- Updates:
Add hurl tests for user creation
Expose  and  endpoints
add user creation route to tracing log
add first_login option to CreateUserRequest dto
- Remvoe unnecessary comment
- Merge pull request #16 from AdeThorMiwa/feat/user-reg-with-groups

Feat: User Registration with Groups
- Merge pull request #24 from Yummy-Yums/dev-setup

docs: fixed dev setup with sqlx and docker compose
- Merge pull request #25 from Yummy-Yums/redundant-routes-fix

Redundant routes fix
- Merge pull request #27 from Yummy-Yums/remove-nav-links-after-login

Remove Register and Login Links after User login
- Merge pull request #26 from Yummy-Yums/db-url-provision

SQLX Migration requires Database_URL environment var
- Update README.md
- Merge pull request #28 from JovitaPaul/main

Update README.md Quickstarter Setup
- Update README.md

Fix close quickstart tag
- Merge pull request #30 from Yummy-Yums/proper-redirect-to-dashboard

fix: redirect to dashboard properly
- Merge pull request #31 from Yummy-Yums/main

fix: adding default run
- Add github actions
- Merge branch 'main' of https://github.com/jonatasoli/keyrunes into cli-tool-for-password-recovery

 Changes to be committed:
	modified:   Cargo.lock
	modified:   Cargo.toml
	modified:   src/api/auth.rs
	deleted:    src/errors.rs
	modified:   src/handler/auth.rs
	new file:   src/handler/errors.rs
	new file:   src/handler/logging.rs
	modified:   src/handler/mod.rs
	modified:   src/lib.rs
	modified:   src/main.rs
	modified:   src/views/auth.rs
	new file:   templates/errors/400.html
	new file:   templates/errors/403.html
	new file:   templates/errors/404.html
	new file:   templates/errors/500.html
	new file:   templates/errors/503.html
	new file:   tests/all_errors_code.rs
	new file:   tests/test_404_error.rs
- Resolved CI errors
- Merge pull request #32 from Yummy-Yums/cli-tool-for-password-recovery

feature: cli tool for password recovery
- Merge pull request #33 from Yummy-Yums/main

refactor: Add tests for settings functionality
- Fix clippy errors

### 🚜 Refactor

- Add tests for settings functionality

### 📚 Documentation

- Add contribuitors document
- Add code of conduct
- Fixed dev setup with sqlx and docker compose

### 🧪 Testing

- Fix tests and remove tests
- Add ignore tests and fix formating

### ⚙️ Miscellaneous Tasks

- Add env example file
- Ignore `.env` file
- Add `docker-compose` to wake up the postgres service
- Update README.md
- Add badge in README
- Add changelog
