CREATE TABLE IF NOT EXISTS "authAccounts" (
	"providerId" text NOT NULL,
	"userId" uuid NOT NULL,
	"provider" text NOT NULL,
	"name" text NOT NULL,
	"info" jsonb DEFAULT '{}'::jsonb,
	CONSTRAINT "authAccounts_provider_providerId_pk" PRIMARY KEY("provider","providerId")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "authSessions" (
	"id" text PRIMARY KEY NOT NULL,
	"userId" uuid NOT NULL,
	"expiresAt" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "users" (
	"id" uuid PRIMARY KEY DEFAULT uuid_generate_v7() NOT NULL,
	"username" varchar(256),
	"email" text NOT NULL,
	"isRegistered" boolean DEFAULT false NOT NULL,
	CONSTRAINT "users_id_unique" UNIQUE("id"),
	CONSTRAINT "users_username_unique" UNIQUE("username"),
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "authAccounts" ADD CONSTRAINT "authAccounts_userId_users_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "authSessions" ADD CONSTRAINT "authSessions_userId_users_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
