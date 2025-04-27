CREATE TABLE "authAccounts" (
	"providerId" text NOT NULL,
	"userId" uuid NOT NULL,
	"provider" text NOT NULL,
	"name" text NOT NULL,
	"info" jsonb DEFAULT '{}'::jsonb,
	CONSTRAINT "authAccounts_provider_providerId_pk" PRIMARY KEY("provider","providerId")
);
--> statement-breakpoint
CREATE TABLE "authSessions" (
	"id" text PRIMARY KEY NOT NULL,
	"userId" uuid NOT NULL,
	"expiresAt" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"username" varchar(256),
	"email" text NOT NULL,
	"isRegistered" boolean DEFAULT false NOT NULL,
	CONSTRAINT "users_id_unique" UNIQUE("id"),
	CONSTRAINT "users_username_unique" UNIQUE("username"),
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
ALTER TABLE "authAccounts" ADD CONSTRAINT "authAccounts_userId_users_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "authSessions" ADD CONSTRAINT "authSessions_userId_users_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;