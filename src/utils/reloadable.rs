use arc_swap::{ArcSwap, Guard};
use notify::event::ModifyKind;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::fmt;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Notify;

#[derive(Clone, Debug)]
pub struct Reloadable<T> {
    inner: Arc<ReloadableInner<T>>,
    #[allow(unused)] // The watcher needs to be kept alive but isn't used otherwise
    watcher: Arc<notify::RecommendedWatcher>,
}

#[derive(Debug)]
struct ReloadableInner<T> {
    data: ArcSwap<T>,
    notify: Notify,
}

pub struct ReloadableGuard<T> {
    inner: Guard<Arc<T>>,
}

impl<T> Reloadable<T>
where
    T: Send + Sync + 'static,
{
    pub fn new<F, FE>(path: PathBuf, reload: F, handle_error: FE) -> Result<Self, notify::Error>
    where
        F: Fn(&Path) -> T + Send + Sync + 'static,
        FE: Fn(notify::Error) + Send + Sync + 'static,
    {
        let inner = Arc::new(ReloadableInner {
            data: ArcSwap::new(Arc::new(reload(&path))),
            notify: Notify::new(),
        });

        let inner_clone = inner.clone();
        let path_clone = path.clone();
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    // Only reload on relevant events
                    match event.kind {
                        EventKind::Any
                        | EventKind::Create(_)
                        | EventKind::Modify(ModifyKind::Any)
                        | EventKind::Modify(ModifyKind::Data(_))
                        | EventKind::Modify(ModifyKind::Name(_))
                        | EventKind::Modify(ModifyKind::Other)
                        | EventKind::Remove(_) => {}
                        _ => return,
                    }

                    inner_clone.data.store(Arc::new(reload(&path_clone)));
                    inner_clone.notify.notify_waiters();
                }
                Err(e) => {
                    handle_error(e);
                }
            }
        })?;

        watcher.watch(&path, RecursiveMode::NonRecursive)?;

        Ok(Self {
            inner,
            watcher: Arc::new(watcher),
        })
    }

    pub fn get(&self) -> ReloadableGuard<T> {
        ReloadableGuard {
            inner: self.inner.data.load(),
        }
    }

    pub async fn wait(&self) {
        self.inner.notify.notified().await;
    }
}

impl<T> Deref for ReloadableGuard<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<T> fmt::Debug for ReloadableGuard<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl<T> fmt::Display for ReloadableGuard<T>
where
    T: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}
