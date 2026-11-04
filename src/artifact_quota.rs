//! In-process accounting under ArtifactStore's filesystem lock. Not a disk lease.
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, OnceLock, Weak},
};
use uuid::Uuid;

type Pools = HashMap<(u64, u64), Weak<Pool>>;
static POOLS: OnceLock<Mutex<Pools>> = OnceLock::new();

#[derive(Debug, Default)]
pub(crate) struct Pool(Mutex<HashMap<Uuid, usize>>);

pub(crate) struct Reservation {
    pool: Arc<Pool>,
    id: Uuid,
}

pub(crate) fn shared(key: (u64, u64)) -> Result<Arc<Pool>> {
    let mut pools = POOLS
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| anyhow!("Повреждён реестр квот"))?;
    pools.retain(|_, pool| pool.strong_count() > 0);
    if let Some(pool) = pools.get(&key).and_then(Weak::upgrade) {
        return Ok(pool);
    }
    let pool = Arc::new(Pool::default());
    pools.insert(key, Arc::downgrade(&pool));
    Ok(pool)
}

fn total(state: &HashMap<Uuid, usize>) -> Result<usize> {
    state.values().try_fold(0usize, |sum, n| {
        sum.checked_add(*n)
            .ok_or_else(|| anyhow!("Переполнение резерва квоты"))
    })
}

impl Pool {
    fn lock(&self) -> Result<MutexGuard<'_, HashMap<Uuid, usize>>> {
        self.0.lock().map_err(|_| anyhow!("Повреждён резерв квоты"))
    }

    pub(crate) fn reserve(
        self: &Arc<Self>,
        used: usize,
        amount: usize,
        limit: usize,
    ) -> Result<Reservation> {
        let mut state = self.lock()?;
        ensure!(
            amount > 0 && state.len() < 32,
            "Некорректный размер или число резервов квоты"
        );
        let available = limit
            .checked_sub(used)
            .and_then(|n| n.checked_sub(total(&state).ok()?))
            .ok_or_else(|| anyhow!("Квота сессии исчерпана"))?;
        ensure!(
            amount <= available,
            "Недостаточно места для обязательного результата процесса"
        );
        let id = Uuid::new_v4();
        ensure!(!state.contains_key(&id), "Идентификатор резерва занят");
        state.insert(id, amount);
        Ok(Reservation {
            pool: self.clone(),
            id,
        })
    }

    pub(crate) fn available(
        &self,
        used: usize,
        limit: usize,
        reservation: Option<Uuid>,
    ) -> Result<usize> {
        let state = self.lock()?;
        let own = reservation
            .map(|id| {
                state
                    .get(&id)
                    .copied()
                    .ok_or_else(|| anyhow!("Резерв квоты отсутствует"))
            })
            .transpose()?;
        let others = total(&state)?
            .checked_sub(own.unwrap_or(0))
            .ok_or_else(|| anyhow!("Повреждён размер резерва"))?;
        let free = limit
            .checked_sub(used)
            .and_then(|n| n.checked_sub(others))
            .ok_or_else(|| anyhow!("Квота сессии исчерпана"))?;
        Ok(own.map_or(free, |n| n.min(free)))
    }

    pub(crate) fn consume(&self, reservation: Uuid, bytes: usize) -> Result<()> {
        let mut state = self.lock()?;
        let remaining = state
            .get_mut(&reservation)
            .ok_or_else(|| anyhow!("Резерв квоты отсутствует"))?;
        let next = remaining
            .checked_sub(bytes)
            .ok_or_else(|| anyhow!("Резерв квоты исчерпан"))?;
        *remaining = next;
        Ok(())
    }
}

impl Reservation {
    pub(crate) fn id(&self) -> Uuid {
        self.id
    }
    pub(crate) fn belongs_to(&self, pool: &Arc<Pool>) -> bool {
        Arc::ptr_eq(&self.pool, pool)
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.pool
            .0
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservations_protect_budget_and_consume_balances_growth() {
        let pool = Arc::new(Pool::default());
        let a = pool.reserve(20, 50, 100).unwrap();
        let b = pool.reserve(20, 20, 100).unwrap();
        assert_eq!(pool.available(20, 100, None).unwrap(), 10);
        assert_eq!(pool.available(20, 100, Some(a.id())).unwrap(), 50);
        assert!(pool.consume(a.id(), 51).is_err());
        assert_eq!(pool.available(20, 100, Some(a.id())).unwrap(), 50);
        pool.consume(a.id(), 30).unwrap();
        assert_eq!(pool.available(50, 100, None).unwrap(), 10);
        assert_eq!(pool.available(50, 100, Some(a.id())).unwrap(), 20);
        let old = a.id();
        drop(a);
        assert_eq!(pool.available(50, 100, None).unwrap(), 30);
        assert!(pool.available(50, 100, Some(old)).is_err());
        assert!(pool.consume(old, 0).is_err());
        drop(b);
        assert_eq!(pool.available(50, 100, None).unwrap(), 50);
    }
    #[test]
    fn shared_handles_and_limits_are_atomic() {
        let pool = shared((u64::MAX, 1)).unwrap();
        let same = shared((u64::MAX, 1)).unwrap();
        let other = shared((u64::MAX, 2)).unwrap();
        let token = pool.reserve(0, 10, 100).unwrap();
        assert!(token.belongs_to(&same));
        assert!(!token.belongs_to(&other));
        assert_eq!(same.available(0, 100, None).unwrap(), 90);
        assert!(pool.reserve(usize::MAX, 1, 100).is_err());
        assert!(pool.reserve(0, 0, 100).is_err());
        assert!(pool.reserve(0, usize::MAX, 100).is_err());
        let more: Vec<_> = (0..31).map(|_| pool.reserve(0, 1, 100).unwrap()).collect();
        assert!(pool.reserve(0, 1, 100).is_err());
        assert_eq!(same.available(0, 100, None).unwrap(), 59);
        drop(more);
        drop(token);
        assert_eq!(same.available(0, 100, None).unwrap(), 100);
    }
}
