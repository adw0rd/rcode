use rcode::task_state::{PlanUpdate, TaskState};
use serde_json::json;

#[test]
fn advisory_update_cannot_replace_goal_or_create_verified_evidence() {
    let mut state = TaskState::for_user_request("Сохранить совместимость").unwrap();
    for hostile in [
        json!({"goal":"другая задача","steps":[]}),
        json!({"evidence":["passed"],"steps":[]}),
    ] {
        assert!(serde_json::from_value::<PlanUpdate>(hostile).is_err());
    }
    let update = serde_json::from_value(
        json!({"steps":[{"id":"test","step":"Проверить контракт","status":"completed"}]}),
    )
    .unwrap();
    state.update_plan(update).unwrap();
    assert_eq!(state.goal(), "Сохранить совместимость");
    assert!(state.projection().unwrap().contains("advisory"));
}

#[test]
fn rejected_update_is_transactional_and_versions_are_checked() {
    let mut state = TaskState::for_user_request("Исправить ошибку").unwrap();
    let before = serde_json::to_vec(&state).unwrap();
    let bad = serde_json::from_value(json!({"steps":[{"id":"a","step":"A","status":"in_progress"},{"id":"b","step":"B","status":"in_progress"}]})).unwrap();
    assert!(state.update_plan(bad).is_err());
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    let mut encoded = serde_json::to_value(&state).unwrap();
    encoded["version"] = json!(99);
    assert!(serde_json::from_value::<TaskState>(encoded).is_err());
    let restored: TaskState = serde_json::from_slice(&before).unwrap();
    assert_eq!(restored.goal(), state.goal());
}

#[test]
fn followup_preserves_original_goal_and_size_bound_is_atomic() {
    let mut state = TaskState::for_user_request("Сделать приложение 🦀").unwrap();
    state.host_followup("Добавь тесты").unwrap();
    assert_eq!(state.goal(), "Сделать приложение 🦀");
    assert_eq!(state.current_request(), "Добавь тесты");
    let before = serde_json::to_vec(&state).unwrap();
    assert!(state.host_followup(&"x".repeat(8193)).is_err());
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
}
#[test]
fn large_user_request_has_a_full_saved_source_and_bounded_projection() {
    use rcode::artifacts::{ArtifactOrigin, ArtifactStore};
    let tmp = tempfile::tempdir().unwrap();
    let sid = uuid::Uuid::new_v4().to_string();
    let store = ArtifactStore::open(tmp.path(), &sid).unwrap();
    let request = format!("START {} END_CONSTRAINT", "точное требование ".repeat(3000));
    let origin = |tool: &str| ArtifactOrigin {
        actor: None,
        turn: 1,
        tool: tool.into(),
        call_id: "user-1".into(),
    };
    let source = store
        .capture(origin("user_request"), &request, &[])
        .unwrap();
    let journal = store
        .capture(
            origin("user_request_journal"),
            &serde_json::json!({"request":source,"previous":null}).to_string(),
            &[],
        )
        .unwrap();
    let mut state = TaskState::default();
    state
        .host_followup_saved(&request, &source, &journal)
        .unwrap();
    let projection = state.projection().unwrap();
    assert!(projection.len() < 12 * 1024);
    assert!(projection.contains(&source.id));
    assert!(projection.contains(&journal.id));
    let goal = state.goal().to_owned();
    let next = store
        .capture(origin("user_request"), "FOLLOWUP", &[])
        .unwrap();
    state
        .host_followup_saved("FOLLOWUP", &next, &journal)
        .unwrap();
    assert_eq!(state.goal(), goal);
    assert_eq!(state.current_request(), "FOLLOWUP");
    assert!(
        state
            .host_followup_saved("WRONG CONTENT", &next, &journal)
            .is_err()
    );
    assert!(
        store
            .read_bytes(None, &source.id, 0, 65536)
            .unwrap()
            .content
            .contains("точное требование")
    );
}
