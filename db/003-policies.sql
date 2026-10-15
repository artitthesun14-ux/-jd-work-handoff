-- Handoff 2.0: row-level security and column grants.
-- Only signed-in (anonymous auth) users get anything; anon gets nothing.

-- The pre-2.0 open policies were neutralized (using/with check false) and renamed
-- "legacy ... (disabled)" rather than dropped. They can be dropped any time.
alter policy "anyone with link can read" on public.tasks using (false);
alter policy "anyone with link can add" on public.tasks with check (false);
alter policy "anyone with link can update" on public.tasks using (false);
alter policy "anyone with link can delete" on public.tasks using (false);
alter policy "events read" on public.task_events using (false);
alter policy "events insert" on public.task_events with check (false);
alter policy "anyone with link can read" on public.tasks rename to "legacy open read (disabled)";
alter policy "anyone with link can add" on public.tasks rename to "legacy open add (disabled)";
alter policy "anyone with link can update" on public.tasks rename to "legacy open update (disabled)";
alter policy "anyone with link can delete" on public.tasks rename to "legacy open delete (disabled)";
alter policy "events read" on public.task_events rename to "legacy events read (disabled)";
alter policy "events insert" on public.task_events rename to "legacy events insert (disabled)";

revoke all on public.tasks, public.task_events, public.workspaces, public.workspace_members,
  public.workspace_invites, public.projects, public.templates from anon;

create policy "members read" on public.workspaces for select to authenticated using (public.is_member(id));
create policy "owner edits" on public.workspaces for update to authenticated using (public.ws_role(id) = 'owner') with check (public.ws_role(id) = 'owner');
revoke insert, update, delete on public.workspaces from authenticated;
grant update (name, description) on public.workspaces to authenticated;

create policy "members read" on public.workspace_members for select to authenticated using (public.is_member(workspace_id));
create policy "self or owner edits" on public.workspace_members for update to authenticated
  using (user_id = auth.uid() or public.ws_role(workspace_id) = 'owner') with check (public.is_member(workspace_id));
create policy "self leaves or owner removes" on public.workspace_members for delete to authenticated
  using (user_id = auth.uid() or public.ws_role(workspace_id) = 'owner');
revoke insert, update on public.workspace_members from authenticated;
grant update (name, role) on public.workspace_members to authenticated;

create policy "admins read" on public.workspace_invites for select to authenticated using (public.is_ws_admin(workspace_id));
revoke insert, update, delete on public.workspace_invites from authenticated;

create policy "members read" on public.projects for select to authenticated using (public.is_member(workspace_id));
create policy "admins add" on public.projects for insert to authenticated with check (public.is_ws_admin(workspace_id));
create policy "admins edit" on public.projects for update to authenticated using (public.is_ws_admin(workspace_id)) with check (public.is_ws_admin(workspace_id));
revoke insert, update, delete on public.projects from authenticated;
grant insert (workspace_id, name, description, color, icon) on public.projects to authenticated;
grant update (name, description, color, icon, archived_at) on public.projects to authenticated;

create policy "members read" on public.templates for select to authenticated using (public.is_member(workspace_id));
create policy "admins add" on public.templates for insert to authenticated with check (public.is_ws_admin(workspace_id));
create policy "admins edit" on public.templates for update to authenticated using (public.is_ws_admin(workspace_id)) with check (public.is_ws_admin(workspace_id));
create policy "admins delete" on public.templates for delete to authenticated using (public.is_ws_admin(workspace_id));
revoke insert, update on public.templates from authenticated;
grant insert (workspace_id, name, description, items, priority, due_days) on public.templates to authenticated;
grant update (name, description, items, priority, due_days) on public.templates to authenticated;

create policy "members read" on public.tasks for select to authenticated using (public.is_member(workspace_id));
create policy "members add" on public.tasks for insert to authenticated with check (public.is_member(workspace_id));
create policy "members edit" on public.tasks for update to authenticated using (public.is_member(workspace_id)) with check (public.is_member(workspace_id));
create policy "creator or admin deletes" on public.tasks for delete to authenticated
  using (created_by_id = auth.uid() or public.is_ws_admin(workspace_id));
revoke insert, update on public.tasks from authenticated;
grant insert (workspace_id, project_id, title, "desc", items, photos, note_photos, priority, due_date, handoff_note, assignee_id) on public.tasks to authenticated;
grant update (project_id, title, "desc", items, photos, note_photos, priority, due_date, handoff_note, assignee_id, status) on public.tasks to authenticated;

create policy "members read" on public.task_events for select to authenticated using (public.is_member(workspace_id));
revoke insert, update, delete on public.task_events from authenticated;

-- Internal helpers are not callable from the app.
revoke execute on function public.member_name(uuid, uuid), public.log_event(uuid, uuid, uuid, text, text, text, jsonb),
  public.new_invite_code(), public.members_guard(), public.tasks_before(), public.tasks_log(), public.touch_updated_at()
  from public, anon, authenticated;
revoke execute on function public.create_workspace(text, text, text), public.join_workspace(text, text),
  public.regenerate_invite(uuid), public.handoff_task(uuid, uuid, text, text, text),
  public.ws_role(uuid), public.is_member(uuid), public.is_ws_admin(uuid) from public, anon;
grant execute on function public.create_workspace(text, text, text), public.join_workspace(text, text),
  public.regenerate_invite(uuid), public.handoff_task(uuid, uuid, text, text, text),
  public.ws_role(uuid), public.is_member(uuid), public.is_ws_admin(uuid) to authenticated;

alter publication supabase_realtime add table public.projects;

------------------------------------------------------------------ photos
-- Files live at photos/<workspace id>/<file>. Only members may upload there.
-- Reading stays public by URL (bucket is public), so a photo link works for anyone who has it.
create or replace function public.photo_ws(p text) returns uuid
language sql immutable set search_path = '' as $$
  select case when split_part(p, '/', 1) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    then split_part(p, '/', 1)::uuid end $$;

create policy "photos members read" on storage.objects for select to authenticated
  using (bucket_id = 'photos' and coalesce(public.is_member(public.photo_ws(name)), false));
create policy "photos members upload" on storage.objects for insert to authenticated
  with check (bucket_id = 'photos' and coalesce(public.is_member(public.photo_ws(name)), false));
create policy "photos owner or admin delete" on storage.objects for delete to authenticated
  using (bucket_id = 'photos' and coalesce(public.is_member(public.photo_ws(name)), false)
    and (owner_id = auth.uid()::text or coalesce(public.is_ws_admin(public.photo_ws(name)), false)));
alter policy "photos read" on storage.objects using (false);
alter policy "photos upload" on storage.objects with check (false);
alter policy "photos delete" on storage.objects using (false);
