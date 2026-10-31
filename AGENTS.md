# Base Instructions

You are in the nuxt-auth repo (`@witchcraft/nuxt-auth`), a Nuxt 4 module.

# Project Context

- **Playground**: `playground/` is the dev app and the target of server and e2e tests.
- **Tech Stack**: Vue 3 (Composition API), better-auth, Drizzle ORM.

## Commands

Lint, Format, and Typecheck: Main command is `pnpm lint:fix`.
Tests:
- `devenv shell -- pnpm test:unit` - non-server unit tests (`pnpm test` is an alias)
- `devenv shell -- pnpm test:unit+server` - server and non-server unit tests
- `devenv shell -- pnpm test:e2e` - playwright tests (needs the `nuxt` process running, see below)
DO NOT run any other commands for tests, they must be run exactly as quoted.
Other:
- `pnpm --dir playground db:regenerate` - if you change the db schema, it must be "regenerated" (deleted and generated again, as it's gitignored and it's mean that the playground always has a fresh schema)

Project Prepare: Project needs to be *built* for the playground to work with the linked module. `pnpm dev:prepare` is not enough. You can quickly rebuild with `pnpm build:only`.

Any change under `src/` needs `pnpm build:only` before anything sees it, the playground, the tests and the electron build all read `dist`. If the server is running, restart it after the rebuild (`devenv processes restart nuxt`).

Follow additional instructions (choom, devenv) for the commands as stipulated by your prompt.

## Auto Loaded Skills

# Devenv Skill

!`cat_skill ~/.skills/software-development/devenv-repo/SKILL.md`

REPO SPECIFIC OVERRIDES:
- This is a module so it's always a test server we're running, their is no seperate testing profile.
- If running the test server yourself run like `devenv up --detach --offline`. 


