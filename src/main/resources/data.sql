insert into acl_class(id, class, class_id_type)
values (1, 'pro.akosarev.sandbox.Post', 'java.util.UUID');

insert into acl_sid(id, principal, sid)
values (1, true, 'user'),
       (2, true, 'admin');

insert into t_post (id, c_text)
values ('356c1ab0-3452-4484-9950-0981daecc874', 'Новая публикация'),
       ('6da27b68-901d-11ee-9f24-db6229c4ab0b', 'Вторая публикация'),
       ('d7a55dac-902a-11ee-8bf9-032d7749a42b', 'Недоступная публикация');

insert into acl_object_identity (id, object_id_class, object_id_identity, parent_object, owner_sid, entries_inheriting)
values (1, 1, '356c1ab0-3452-4484-9950-0981daecc874', null, 1, true),
       (2, 1, '6da27b68-901d-11ee-9f24-db6229c4ab0b', 1, 2, true),
       (3, 1, 'd7a55dac-902a-11ee-8bf9-032d7749a42b', null, 1, true);

insert into acl_entry(id, acl_object_identity, ace_order, sid, mask, granting, audit_success, audit_failure)
values (1, 1, 0, 1, -1048576, true, true, true),
       (2, 3, 0, 1, 1, false, true, true);
