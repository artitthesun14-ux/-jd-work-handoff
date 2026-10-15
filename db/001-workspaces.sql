-- Handoff 2.0: workspaces, members, projects, templates.
-- Applied 2026-10-15. The two pre-2.0 tasks were deleted at the owner's request
-- (a JSON backup was kept outside the repo before deleting).
-- Who can do what is enforced here (RLS + triggers), not by hiding buttons.

-- Old rows were deleted first through the REST API (events cascade).

------------------------------------------------------------------ tables
create table public.workspaces(
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(btrim(name)) between 1 and 60),
  description text not null default '' check (length(description) <= 500),
  created_by uuid references auth.users(id) on delete set null default auth.uid(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now());

create table public.workspace_members(
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner','admin','member')),
  name text not null check (length(btrim(name)) between 1 and 40),
  joined_at timestamptz not null default now(),
  primary key (workspace_id, user_id));
create index on public.workspace_members(user_id);

-- Kept apart from workspaces so plain members cannot read the code.
create table public.workspace_invites(
  workspace_id uuid primary key references public.workspaces(id) on delete cascade,
  code text not null unique);

create table public.projects(
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  name text not null check (length(btrim(name)) between 1 and 60),
  description text not null default '' check (length(description) <= 500),
  color text not null default 'yellow' check (color in ('yellow','blue','green','red','purple','orange','gray')),
  icon text not null default '📁' check (length(icon) <= 8),
  archived_at timestamptz,
  created_by uuid references auth.users(id) on delete set null default auth.uid(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, workspace_id));
create index on public.projects(workspace_id);

create table public.templates(
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  name text not null check (length(btrim(name)) between 1 and 60),
  description text not null default '' check (length(description) <= 1000),
  items jsonb not null default '[]' check (jsonb_typeof(items) = 'array'),
  priority text check (priority in ('urgent','normal','low')),
  due_days int check (due_days between 0 and 365),
  created_by uuid references auth.users(id) on delete set null default auth.uid(),
  created_at timestamptz not null default now());
create index on public.templates(workspace_id);

-- Tasks keep their text name columns (created_by, claimed_by) as display snapshots;
-- the server fills them from the member list, so nobody can type someone else's name.
alter table public.tasks
  add column workspace_id uuid not null references public.workspaces(id) on delete cascade,
  add column project_id uuid,
  add column created_by_id uuid references auth.users(id) on delete set null default auth.uid(),
  add column assignee_id uuid references auth.users(id) on delete set null,
  add column updated_at timestamptz not null default now(),
  -- A task's project must be in the task's own workspace.
  add constraint tasks_project_same_ws foreign key (project_id, workspace_id) references public.projects(id, workspace_id);
create index on public.tasks(workspace_id, created_at desc);
create index on public.tasks(project_id);

alter table public.task_events
  add column workspace_id uuid not null references public.workspaces(id) on delete cascade,
  add column actor_id uuid references auth.users(id) on delete set null,
  add column metadata jsonb;
create index if not exists task_events_task_id_idx on public.task_events(task_id);

alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.workspace_invites enable row level security;
alter table public.projects enable row level security;
alter table public.templates enable row level security;
