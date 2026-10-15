-- Handoff 2.0: access rules. Every signed-in device is a real (anonymous) Supabase
-- user; a person only sees a workspace after creating it or joining with its code.

------------------------------------------------------------------ helpers
create or replace function public.ws_role(ws uuid) returns text
language sql stable security definer set search_path = '' as $$
  select role from public.workspace_members where workspace_id = ws and user_id = auth.uid() $$;

create or replace function public.is_member(ws uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.workspace_members where workspace_id = ws and user_id = auth.uid()) $$;

create or replace function public.is_ws_admin(ws uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce(public.ws_role(ws) in ('owner','admin'), false) $$;

create or replace function public.member_name(ws uuid, u uuid) returns text
language sql stable security definer set search_path = '' as $$
  select name from public.workspace_members where workspace_id = ws and user_id = u $$;

create or replace function public.new_invite_code() returns text
language sql volatile set search_path = '' as $$
  select upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 10)) $$;

create or replace function public.touch_updated_at() returns trigger
language plpgsql set search_path = '' as $$ begin new.updated_at := now(); return new; end $$;

create or replace function public.log_event(t uuid, ws uuid, actor_id uuid, actor text, action text, detail text, meta jsonb default null)
returns void language sql security definer set search_path = '' as $$
  insert into public.task_events(task_id, workspace_id, actor_id, actor, action, detail, metadata)
  values (t, ws, actor_id, coalesce(actor, 'ระบบ'), action, coalesce(detail, ''), meta) $$;

------------------------------------------------------------------ workspace RPCs
create or replace function public.create_workspace(p_name text, p_description text, p_member_name text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare ws uuid; uid uuid := auth.uid();
begin
  if uid is null then raise exception 'ยังไม่ได้เข้าสู่ระบบ' using errcode = '28000'; end if;
  if (select count(*) from public.workspace_members where user_id = uid and role = 'owner') >= 20 then
    raise exception 'สร้าง Workspace ได้ไม่เกิน 20 แห่ง'; end if;
  insert into public.workspaces(name, description, created_by)
    values (btrim(p_name), coalesce(btrim(p_description), ''), uid) returning id into ws;
  insert into public.workspace_members(workspace_id, user_id, role, name) values (ws, uid, 'owner', btrim(p_member_name));
  insert into public.workspace_invites(workspace_id, code) values (ws, public.new_invite_code());
  insert into public.templates(workspace_id, name, description, items, priority, due_days, created_by)
  select ws, n, d, (select jsonb_agg(jsonb_build_object('text', x, 'done', false)) from unnest(i) x), p, dd, uid
  from (values
    ('ตรวจนับสต็อก', 'นับสินค้าคงเหลือเทียบกับยอดในระบบ', array['เตรียมใบนับและอุปกรณ์','นับสินค้าตามโซน','เทียบยอดกับระบบ','บันทึกส่วนต่างและสาเหตุ','แจ้งหัวหน้าเมื่อพบส่วนต่าง'], 'normal', 1),
    ('รับสินค้า', 'ตรวจรับสินค้าเข้าร้านหรือคลัง', array['ตรวจเอกสารส่งของ','นับจำนวนเทียบใบสั่งซื้อ','ตรวจสภาพสินค้า','ถ่ายรูปสินค้าที่เสียหาย','บันทึกรับเข้าระบบ','จัดเก็บเข้าที่'], 'normal', 0),
    ('คืนสินค้า', 'รับคืนสินค้าจากลูกค้าหรือส่งคืนซัพพลายเออร์', array['ตรวจสภาพสินค้าที่คืน','ตรวจใบเสร็จหรือเลขออเดอร์','บันทึกเหตุผลการคืน','คืนเงินหรือเปลี่ยนสินค้า','แยกสินค้าคืนไว้ที่โซนคืน'], 'normal', 1),
    ('ตรวจสอบออเดอร์', 'ตรวจออเดอร์ก่อนจัดส่ง', array['ตรวจรายการสินค้าในออเดอร์','ตรวจที่อยู่จัดส่ง','ตรวจการชำระเงิน','แพ็กและติดฉลาก','อัปเดตสถานะออเดอร์'], 'normal', 0),
    ('เปิดร้าน', 'สิ่งที่ต้องทำก่อนเปิดร้าน', array['เปิดไฟและระบบ','ตรวจความสะอาด','เช็คเงินทอน','เติมสินค้าหน้าร้าน','เปิดเครื่อง POS'], 'normal', 0),
    ('ปิดร้าน', 'สิ่งที่ต้องทำก่อนปิดร้าน', array['สรุปยอดขาย','นับเงินสด','เก็บสินค้าหน้าร้าน','ทำความสะอาด','ปิดไฟและล็อกร้าน'], 'normal', 0),
    ('ส่งต่องานเมื่อเปลี่ยนกะ', 'สรุปให้คนกะถัดไปรับงานต่อได้ทันที', array['สรุปงานที่ทำเสร็จในกะนี้','งานค้างและสิ่งที่ต้องทำต่อ','ปัญหาที่พบ','ของหรือเอกสารวางไว้ที่ไหน'], 'normal', 0),
    ('Checklist โปรเจกต์ใหม่', 'เริ่มโปรเจกต์ให้ครบทุกขั้น', array['กำหนดเป้าหมายโปรเจกต์','กำหนดผู้รับผิดชอบ','กำหนดวันส่งงาน','แตกงานย่อย','นัดประชุมเริ่มงาน'], 'normal', 7)
  ) as t(n, d, i, p, dd);
  return ws;
end $$;

create or replace function public.join_workspace(p_code text, p_member_name text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare ws uuid; uid uuid := auth.uid();
begin
  if uid is null then raise exception 'ยังไม่ได้เข้าสู่ระบบ' using errcode = '28000'; end if;
  select workspace_id into ws from public.workspace_invites
    where code = upper(regexp_replace(coalesce(p_code, ''), '[^0-9A-Za-z]', '', 'g'));
  if ws is null then raise exception 'รหัสเชิญไม่ถูกต้อง' using errcode = 'P0002'; end if;
  insert into public.workspace_members(workspace_id, user_id, role, name)
    values (ws, uid, 'member', btrim(p_member_name)) on conflict do nothing;
  return ws;
end $$;

create or replace function public.regenerate_invite(p_ws uuid)
returns text language plpgsql security definer set search_path = '' as $$
declare c text;
begin
  if not public.is_ws_admin(p_ws) then raise exception 'เฉพาะ Owner หรือ Admin' using errcode = '42501'; end if;
  update public.workspace_invites set code = public.new_invite_code() where workspace_id = p_ws returning code into c;
  return c;
end $$;

------------------------------------------------------------------ member rules
create or replace function public.members_guard() returns trigger
language plpgsql security definer set search_path = '' as $$
declare uid uuid := auth.uid();
begin
  if uid is null then return coalesce(new, old); end if;
  if tg_op = 'UPDATE' then
    if new.name is distinct from old.name and uid <> old.user_id then
      raise exception 'แก้ชื่อได้เฉพาะของตัวเอง' using errcode = '42501'; end if;
    if new.role is distinct from old.role and coalesce(public.ws_role(old.workspace_id), '') <> 'owner' then
      raise exception 'เฉพาะ Owner เปลี่ยนบทบาทได้' using errcode = '42501'; end if;
  else
    if not exists (select 1 from public.workspaces where id = old.workspace_id) then return old; end if;
    if uid <> old.user_id and coalesce(public.ws_role(old.workspace_id), '') <> 'owner' then
      raise exception 'เฉพาะ Owner นำสมาชิกออกได้' using errcode = '42501'; end if;
  end if;
  if old.role = 'owner' and (tg_op = 'DELETE' or new.role <> 'owner') and not exists (
      select 1 from public.workspace_members where workspace_id = old.workspace_id and role = 'owner' and user_id <> old.user_id) then
    raise exception 'Workspace ต้องมี Owner อย่างน้อย 1 คน'; end if;
  return coalesce(new, old);
end $$;
create trigger members_guard before update or delete on public.workspace_members
  for each row execute function public.members_guard();
create trigger workspaces_touch before update on public.workspaces for each row execute function public.touch_updated_at();
create trigger projects_touch before update on public.projects for each row execute function public.touch_updated_at();

------------------------------------------------------------------ task rules
alter table public.tasks add constraint tasks_status_chk check (status in ('claimed','doing','done'));
alter table public.tasks add constraint tasks_priority_chk check (priority in ('urgent','normal','low'));

create or replace function public.tasks_before() returns trigger
language plpgsql security definer set search_path = '' as $$
declare uid uuid := auth.uid(); adm boolean;
  keep text[] := array['assignee_id','claimed_by','claimed_at','status','updated_at'];
begin
  if uid is not null then
    adm := public.is_ws_admin(new.workspace_id);
    if tg_op = 'INSERT' then
      new.created_by_id := uid; new.created_at := now();
      new.created_by := public.member_name(new.workspace_id, uid);
      if new.created_by is null then raise exception 'ไม่ได้เป็นสมาชิก Workspace นี้' using errcode = '42501'; end if;
    else
      -- Creator, assignee and admins may edit. Anyone else may only claim an unassigned task for themselves.
      if not coalesce(adm or uid = old.created_by_id or uid = old.assignee_id, false)
         and not coalesce(old.assignee_id is null and new.assignee_id = uid and (to_jsonb(new) - keep) = (to_jsonb(old) - keep), false) then
        raise exception 'ไม่มีสิทธิ์แก้ไขงานนี้' using errcode = '42501'; end if;
      if new.status is distinct from old.status and new.assignee_id is not distinct from old.assignee_id
         and not coalesce(adm or uid = old.assignee_id, false) then
        raise exception 'เฉพาะผู้รับงานเปลี่ยนสถานะได้' using errcode = '42501'; end if;
    end if;
  end if;
  if new.project_id is not null and (tg_op = 'INSERT' or new.project_id is distinct from old.project_id)
     and exists (select 1 from public.projects where id = new.project_id and archived_at is not null) then
    raise exception 'โปรเจกต์นี้ถูกเก็บถาวรแล้ว เพิ่มหรือย้ายงานเข้าไปไม่ได้'; end if;
  -- Assignee name and claim time come from the server, never from the client.
  if new.assignee_id is null then
    new.claimed_by := null; new.claimed_at := null; new.status := null;
  elsif tg_op = 'INSERT' or new.assignee_id is distinct from old.assignee_id then
    new.claimed_by := public.member_name(new.workspace_id, new.assignee_id);
    if new.claimed_by is null then raise exception 'ผู้รับงานต้องเป็นสมาชิก Workspace นี้'; end if;
    new.claimed_at := now(); new.status := 'claimed';
  elsif new.status is null then new.status := 'claimed';
  end if;
  new.updated_at := now();
  return new;
end $$;
create trigger tasks_before before insert or update on public.tasks for each row execute function public.tasks_before();

create or replace function public.status_label(s text, a uuid) returns text
language sql immutable set search_path = '' as $$
  select case when a is null then 'ยังไม่มีคนรับ' else case coalesce(s, 'claimed')
    when 'claimed' then 'รับงานแล้ว' when 'doing' then 'กำลังทำ' when 'done' then 'เสร็จแล้ว' else s end end $$;

-- History is written by the database in the same transaction as the change,
-- so it can never claim a change that did not happen.
create or replace function public.tasks_log() returns trigger
language plpgsql security definer set search_path = '' as $$
declare uid uuid := auth.uid(); who text := public.member_name(new.workspace_id, uid);
  pl jsonb := '{"urgent":"เร่งด่วน","normal":"ปกติ","low":"ไม่เร่งด่วน"}';
begin
  if tg_op = 'INSERT' then
    perform public.log_event(new.id, new.workspace_id, uid, who, 'สร้างงาน', '');
    if new.assignee_id is not null then perform public.log_event(new.id, new.workspace_id, uid, who, 'มอบหมายงาน', 'ให้ ' || new.claimed_by); end if;
    return null;
  end if;
  if new.assignee_id is distinct from old.assignee_id then
    if coalesce(current_setting('handoff.skip_log', true), '') <> 'assignee' then
      if old.assignee_id is null and new.assignee_id = uid then
        perform public.log_event(new.id, new.workspace_id, uid, who, 'รับงาน', '');
      else
        perform public.log_event(new.id, new.workspace_id, uid, who, 'เปลี่ยนผู้รับ',
          coalesce(old.claimed_by, 'ไม่มี') || ' → ' || coalesce(new.claimed_by, 'ไม่มีคนรับ'));
      end if;
    end if;
  elsif new.status is distinct from old.status then
    perform public.log_event(new.id, new.workspace_id, uid, who, 'เปลี่ยนสถานะ',
      public.status_label(old.status, old.assignee_id) || ' → ' || public.status_label(new.status, new.assignee_id));
  end if;
  if new.due_date is distinct from old.due_date then
    perform public.log_event(new.id, new.workspace_id, uid, who, 'แก้ไขกำหนดส่ง',
      coalesce(old.due_date::text, 'ไม่มี') || ' → ' || coalesce(new.due_date::text, 'ไม่มี')); end if;
  if new.priority is distinct from old.priority then
    perform public.log_event(new.id, new.workspace_id, uid, who, 'เปลี่ยนความสำคัญ',
      (pl ->> old.priority) || ' → ' || (pl ->> new.priority)); end if;
  if new.project_id is distinct from old.project_id then
    perform public.log_event(new.id, new.workspace_id, uid, who, 'ย้ายโปรเจกต์',
      coalesce((select name from public.projects where id = old.project_id), 'ไม่มีโปรเจกต์') || ' → ' ||
      coalesce((select name from public.projects where id = new.project_id), 'ไม่มีโปรเจกต์')); end if;
  if new.title is distinct from old.title then
    perform public.log_event(new.id, new.workspace_id, uid, who, 'แก้ไขชื่องาน', old.title || ' → ' || new.title); end if;
  if new.handoff_note is distinct from old.handoff_note then
    perform public.log_event(new.id, new.workspace_id, uid, who, 'แก้ไขหมายเหตุส่งต่องาน', ''); end if;
  return null;
end $$;
create trigger tasks_log after insert or update on public.tasks for each row execute function public.tasks_log();

-- Hand a task to someone else (or back to "nobody") with a structured note, atomically.
create or replace function public.handoff_task(p_task uuid, p_to uuid, p_reason text, p_done text, p_next text)
returns void language plpgsql security definer set search_path = '' as $$
declare t public.tasks; uid uuid := auth.uid(); to_name text;
begin
  select * into t from public.tasks where id = p_task for update;
  if t.id is null or not public.is_member(t.workspace_id) then raise exception 'ไม่พบงานนี้' using errcode = 'P0002'; end if;
  if p_to is not distinct from t.assignee_id then raise exception 'งานนี้อยู่กับคนนี้อยู่แล้ว'; end if;
  if length(coalesce(p_reason, '') || coalesce(p_done, '') || coalesce(p_next, '')) > 4000 then raise exception 'ข้อความยาวเกินไป'; end if;
  perform set_config('handoff.skip_log', 'assignee', true);
  update public.tasks set assignee_id = p_to where id = p_task; -- tasks_before checks who may do this
  perform set_config('handoff.skip_log', '', true);
  to_name := public.member_name(t.workspace_id, p_to);
  perform public.log_event(p_task, t.workspace_id, uid, public.member_name(t.workspace_id, uid),
    case when p_to is null then 'ปล่อยงานคืน' else 'ส่งต่องาน' end,
    coalesce(t.claimed_by, 'ไม่มี') || ' → ' || coalesce(to_name, 'ไม่มีคนรับ'),
    jsonb_strip_nulls(jsonb_build_object('from', t.claimed_by, 'to', to_name,
      'reason', nullif(btrim(p_reason), ''), 'done', nullif(btrim(p_done), ''), 'next', nullif(btrim(p_next), ''))));
end $$;
