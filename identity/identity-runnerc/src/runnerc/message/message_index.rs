// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::borrow::Borrow;
use core::hash::Hash;
use core::iter::FromIterator;
use core::ops::Deref;
use core::ops::DerefMut;
use std::collections::HashMap;

use crate::runnerc::MessageId;
use crate::runnerc::TangleRef;

type __Index<T> = HashMap<MessageId, Vec<T>>;

/// Index of [TangleRef] instances where the index key is the `previous_message_id`.
#[derive(Clone, Debug)]
pub struct MessageIndex<T> {
  inner: __Index<T>,
}

impl<T> MessageIndex<T> {
  /// Creates a new [`MessageIndex`].
  pub fn new() -> Self {
    Self { inner: HashMap::new() }
  }

  /// Returns the total size of the index.
  pub fn size(&self) -> usize {
    self.inner.values().map(Vec::len).sum()
  }

  pub fn remove_where<U>(&mut self, key: &U, f: impl Fn(&T) -> bool) -> Option<T>
  where
    MessageId: Borrow<U>,
    U: Hash + Eq + ?Sized,
  {
    if let Some(list) = self.inner.get_mut(key) {
      list.iter().position(f).map(|index| list.remove(index))
    } else {
      None
    }
  }

  pub fn drain_keys(&mut self) -> impl Iterator<Item = MessageId> + '_ {
    self.inner.drain().map(|(data, _)| data)
  }
}

impl<T> MessageIndex<T>
where
  T: TangleRef,
{
  pub fn insert(&mut self, element: T) {
    let key: &MessageId = element.previous_message_id();

    if let Some(scope) = self.inner.get_mut(key) {
      let message_id: &MessageId = element.message_id();

      let index: usize = match scope.binary_search_by(|elem| elem.message_id().cmp(message_id)) {
        Ok(index) => index,
        Err(index) => index,
      };

      scope.insert(index, element);
    } else {
      self.inner.insert(key.clone(), vec![element]);
    }
  }

  pub fn extend<I>(&mut self, iter: I)
  where
    I: IntoIterator<Item = T>,
  {
    for element in iter.into_iter() {
      self.insert(element);
    }
  }
}

impl<T> Default for MessageIndex<T> {
  fn default() -> Self {
    Self::new()
  }
}

impl<T> Deref for MessageIndex<T> {
  type Target = __Index<T>;

  fn deref(&self) -> &Self::Target {
    &self.inner
  }
}

impl<T> DerefMut for MessageIndex<T> {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.inner
  }
}

impl<T> FromIterator<T> for MessageIndex<T>
where
  T: TangleRef,
{
  fn from_iter<I>(iter: I) -> Self
  where
    I: IntoIterator<Item = T>,
  {
    let mut this: Self = Self::new();
    this.extend(iter);
    this
  }
}