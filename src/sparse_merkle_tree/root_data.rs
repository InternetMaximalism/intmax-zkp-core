use std::fmt::Debug;

pub trait RootData<I: Sized> {
    type Error: 'static + Debug + Sync + Send;

    fn get(&self) -> Result<I, Self::Error>;
    fn set(&mut self, root: I) -> Result<(), Self::Error>;
}
