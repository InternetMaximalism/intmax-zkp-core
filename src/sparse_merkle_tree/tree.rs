use std::{fmt::Debug, hash::Hash};

use super::{
    node_data::{Node, NodeData},
    node_hash::NodeHash,
    proof::{ProcessMerkleProofRole, SparseMerkleInclusionProof, SparseMerkleProcessProof},
    root_data::RootData,
};

#[derive(Debug)]
pub struct SparseMerkleTree<
    K: Sized,
    V: Sized,
    I: Sized,
    H: NodeHash<K, V, I>,
    D: NodeData<K, V, I>,
    R: RootData<I>,
> {
    pub nodes_db: D,
    pub roots_db: R,
    pub _key: std::marker::PhantomData<K>,
    pub _value: std::marker::PhantomData<V>,
    pub _root: std::marker::PhantomData<I>,
    pub _hash: std::marker::PhantomData<H>,
}

impl<K: Sized, V: Sized, I: Sized, H: NodeHash<K, V, I>, D: NodeData<K, V, I>, R: RootData<I>>
    SparseMerkleTree<K, V, I, H, D, R>
{
    pub fn new(nodes_db: D, roots_db: R) -> Self {
        Self {
            nodes_db,
            roots_db,
            _key: std::marker::PhantomData,
            _value: std::marker::PhantomData,
            _root: std::marker::PhantomData,
            _hash: std::marker::PhantomData,
        }
    }
}

impl<
        K: Sized,
        V: Sized,
        I: Sized + Default,
        H: NodeHash<K, V, I>,
        D: NodeData<K, V, I> + Default,
        R: RootData<I> + Default,
    > Default for SparseMerkleTree<K, V, I, H, D, R>
{
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

pub trait KeyLike: Copy + Eq + Debug + Default + Hash {
    fn to_bits(&self) -> Vec<bool>;
}

pub trait ValueLike: Copy + PartialEq + Debug + Default {}

pub trait HashLike: Copy + PartialEq + Debug + Default {}

impl<
        K: KeyLike,
        V: ValueLike,
        I: HashLike,
        H: NodeHash<K, V, I>,
        D: NodeData<K, V, I>,
        R: RootData<I>,
    > SparseMerkleTree<K, V, I, H, D, R>
{
    pub fn get_root(&self) -> Result<I, R::Error> {
        self.roots_db.get()
    }

    pub fn change_root(&mut self, root_hash: I) -> anyhow::Result<()> {
        if !I::default().eq(&root_hash) {
            let root_node = self.nodes_db.get(&root_hash).map_err(|err| {
                anyhow::anyhow!("fail to get node corresponding `root_hash`: {:?}", err)
            })?;
            if root_node.is_none() {
                return Err(anyhow::anyhow!(
                    "the node corresponding `root_hash` does not exist"
                ));
            }
        }

        self.roots_db
            .set(root_hash)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;

        Ok(())
    }

    pub fn update(
        &mut self,
        key: &K,
        new_value: &V,
    ) -> anyhow::Result<SparseMerkleProcessProof<K, V, I>> {
        let mut root = self
            .roots_db
            .get()
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        let result = update::<K, V, I, H, D>(&mut self.nodes_db, &mut root, key, *new_value)?;
        self.roots_db
            .set(root)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;

        Ok(result)
    }

    pub fn insert(
        &mut self,
        key: K,
        value: V,
    ) -> anyhow::Result<SparseMerkleProcessProof<K, V, I>> {
        let mut root = self
            .roots_db
            .get()
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        let result = insert::<K, V, I, H, D>(&mut self.nodes_db, &mut root, key, value)?;
        self.roots_db
            .set(root)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;

        Ok(result)
    }

    pub fn remove(&mut self, key: &K) -> anyhow::Result<SparseMerkleProcessProof<K, V, I>> {
        let mut root = self
            .roots_db
            .get()
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        let result = remove::<K, V, I, H, D>(&mut self.nodes_db, &mut root, key)?;
        self.roots_db
            .set(root)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;

        Ok(result)
    }

    pub fn set(&mut self, key: K, value: V) -> anyhow::Result<SparseMerkleProcessProof<K, V, I>> {
        let mut root = self
            .roots_db
            .get()
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        let result =
            calc_process_proof::<K, V, I, H, D>(&mut self.nodes_db, &mut root, key, value)?;
        self.roots_db
            .set(root)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;

        Ok(result)
    }

    pub fn find(&self, key: &K) -> anyhow::Result<SparseMerkleInclusionProof<K, V, I>> {
        let root = self
            .roots_db
            .get()
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        calc_inclusion_proof::<K, V, I, H, D>(&self.nodes_db, &root, key)
    }

    pub fn get(&self, key: &K) -> anyhow::Result<V> {
        let root = self
            .roots_db
            .get()
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        get::<K, V, I, H, D>(&self.nodes_db, &root, key)
    }
}

fn update<K: KeyLike, V: ValueLike, I: HashLike, H: NodeHash<K, V, I>, D: NodeData<K, V, I>>(
    nodes_db: &mut D,
    root: &mut I,
    key: &K,
    new_value: V,
) -> anyhow::Result<SparseMerkleProcessProof<K, V, I>> {
    let res_find = find::<K, V, I, H, D>(nodes_db, root, key)?;

    // Given key should be found.
    if !res_find.found {
        return Err(anyhow::anyhow!("given key does not exists"));
    }

    if V::default().eq(&new_value) {
        return Err(anyhow::anyhow!("value must be non-zero"));
    }

    assert_eq!(res_find.key, *key);

    let found_key = res_find.key;
    let found_value = res_find.value;

    let res_old_root = res_find.root;

    let mut insert_entries = vec![];
    let mut delete_keys = vec![];

    let old_leaf_node = Node::Leaf(found_key, found_value);
    let new_leaf_node = Node::Leaf(found_key, new_value);
    let mut rt_old = H::calc_node_hash(old_leaf_node);
    let mut rt_new = H::calc_node_hash(new_leaf_node.clone());
    insert_entries.push((rt_new, new_leaf_node));
    delete_keys.push(rt_old);

    let key_bits = found_key.to_bits();
    for (&sibling, bit) in res_find.siblings.iter().zip(key_bits).rev() {
        let (old_node, new_node) = if bit {
            (
                Node::Internal(sibling, rt_old),
                Node::Internal(sibling, rt_new),
            )
        } else {
            (
                Node::Internal(rt_old, sibling),
                Node::Internal(rt_new, sibling),
            )
        };
        rt_old = H::calc_node_hash(old_node);
        rt_new = H::calc_node_hash(new_node.clone());
        delete_keys.push(rt_old);
        insert_entries.push((rt_new, new_node));
    }

    {
        nodes_db
            .multi_delete(&delete_keys)
            .map_err(|_| anyhow::anyhow!("fail to delete multiple entries"))?;
        nodes_db
            .multi_insert(insert_entries)
            .map_err(|_| anyhow::anyhow!("fail to insert multiple entries"))?;
        // tree.roots_db
        //     .set(rt_new)
        //     .map_err(|_| anyhow::anyhow!("fail to set root"))?;
        // tree.root = rt_new;
    }

    let _ = core::mem::replace(root, rt_new);

    Ok(SparseMerkleProcessProof {
        old_root: res_old_root,
        old_key: found_key,
        old_value: found_value,
        new_root: rt_new,
        new_key: found_key,
        new_value,
        siblings: res_find.siblings,
        is_old0: false,
        fnc: ProcessMerkleProofRole::ProcessUpdate,
    })
}

fn insert<K: KeyLike, V: ValueLike, I: HashLike, H: NodeHash<K, V, I>, D: NodeData<K, V, I>>(
    nodes_db: &mut D,
    root: &mut I,
    key: K,
    value: V,
) -> anyhow::Result<SparseMerkleProcessProof<K, V, I>> {
    let res_find = find::<K, V, I, H, D>(nodes_db, root, &key)?;
    let res_old_root = res_find.root;

    // Given key should not be found.
    if res_find.found {
        return Err(anyhow::anyhow!("given key already exists"));
    }

    if V::default().eq(&value) {
        return Err(anyhow::anyhow!("value must be non-zero"));
    }

    let mut res_siblings = res_find.siblings;
    // dbg!(&res_siblings);
    let not_found_key = res_find.not_found_key;
    let not_found_value = res_find.not_found_value;

    let (mixed, added_one, rt_old) = if !res_find.is_old0 {
        let old_key_bits = not_found_key.to_bits();
        let new_key_bits = key.to_bits();

        for (old_key_bit, new_key_bit) in old_key_bits
            .into_iter()
            .zip(new_key_bits)
            .skip(res_siblings.len())
        {
            if old_key_bit != new_key_bit {
                break;
            }

            res_siblings.push(I::default());
        }

        let old_node = Node::Leaf(not_found_key, not_found_value);
        // dbg!(&old_node);

        let rt_old = H::calc_node_hash(old_node);
        res_siblings.push(rt_old);
        let added_one = true;
        let mixed = false;

        (mixed, added_one, rt_old)
    } else {
        let mixed = !res_siblings.is_empty();
        let added_one = false;
        let rt_old = I::default();

        (mixed, added_one, rt_old)
    };

    let mut rt_old = rt_old;

    let mut insert_entries = vec![];
    let mut delete_keys = vec![];

    let mut rt = H::calc_node_hash(Node::Leaf(key, value));
    insert_entries.push((rt, Node::Leaf(key, value)));

    let new_key_bits = key.to_bits();
    for (level, (&sibling, bit)) in res_siblings.iter().zip(new_key_bits).rev().enumerate() {
        // means whether both old_value and new_value are reference the sibling.
        let mixed = if level != 0 && !I::default().eq(&sibling) {
            true
        } else {
            mixed
        };

        if mixed {
            let old_sibling = sibling;
            let old_node = if bit {
                Node::Internal(old_sibling, rt_old)
            } else {
                Node::Internal(rt_old, old_sibling)
            };
            rt_old = H::calc_node_hash(old_node);
            delete_keys.push(rt_old);
        }

        let new_node = if bit {
            Node::Internal(sibling, rt)
        } else {
            Node::Internal(rt, sibling)
        };

        let new_rt = H::calc_node_hash(new_node.clone());
        // dbg!(&new_rt, &new_node);

        insert_entries.push((new_rt, new_node));

        rt = new_rt;
    }

    if added_one {
        res_siblings.pop();
    }

    while !res_siblings.is_empty() && I::default().eq(&res_siblings[res_siblings.len() - 1]) {
        res_siblings.pop();
    }

    {
        nodes_db
            .multi_delete(&delete_keys)
            .map_err(|_| anyhow::anyhow!("fail to delete multiple entries"))?;
        nodes_db
            .multi_insert(insert_entries)
            .map_err(|_| anyhow::anyhow!("fail to insert multiple entries"))?;
        // tree.roots_db
        //     .set(rt)
        //     .map_err(|_| anyhow::anyhow!("fail to set root"))?;
        // tree.root = rt;
    }

    let _ = core::mem::replace(root, rt);

    Ok(SparseMerkleProcessProof {
        old_root: res_old_root,
        old_key: not_found_key,
        old_value: not_found_value,
        new_root: rt,
        new_key: key,
        new_value: value,
        siblings: res_siblings,
        is_old0: res_find.is_old0,
        fnc: ProcessMerkleProofRole::ProcessInsert,
    })
}

/// 遷移の自然さを考慮して, オリジナルの仕様とは (old_key, old_value) と (new_key, new_value) を逆に出力している.
fn remove<K: KeyLike, V: ValueLike, I: HashLike, H: NodeHash<K, V, I>, D: NodeData<K, V, I>>(
    nodes_db: &mut D,
    root: &mut I,
    key: &K,
) -> anyhow::Result<SparseMerkleProcessProof<K, V, I>> {
    let res_find = find::<K, V, I, H, D>(nodes_db, root, key)?;

    // Given key should be found.
    if !res_find.found {
        return Err(anyhow::anyhow!("given key does not exists"));
    }

    assert_eq!(res_find.key, *key);

    let found_key = res_find.key;
    let found_value = res_find.value;

    let mut delete_keys = vec![];
    let mut insert_entries = vec![];
    let old_leaf_node = Node::Leaf(found_key, found_value);
    let mut rt_old = H::calc_node_hash(old_leaf_node);
    delete_keys.push(rt_old);

    let (mixed, res_old_key, res_old_value, res_is_old0, rt_new) = if !res_find.siblings.is_empty()
    {
        let res_last_sibling = res_find.siblings.last().unwrap();
        let next_node = nodes_db
            .get(res_last_sibling)
            .map_err(|_| anyhow::anyhow!(""))?;
        match next_node {
            Some(Node::Leaf(key, value)) => {
                let mixed = false;
                let res_old_key = key;
                let res_old_value = value;
                let res_is_old0 = false;
                let rt_new = *res_last_sibling;

                (mixed, res_old_key, res_old_value, res_is_old0, rt_new)
            }
            Some(Node::Internal(_, _)) => {
                let mixed = true;
                let res_old_key = found_key;
                let res_old_value = V::default();
                let res_is_old0 = true;
                let rt_new = I::default(); // 後で値を決める

                (mixed, res_old_key, res_old_value, res_is_old0, rt_new)
            }
            None => {
                unreachable!()
            }
        }
    } else {
        // if res_find.siblings.is_empty()

        let mixed = false; // unused
        let res_old_key = found_key;
        let res_old_value = V::default();
        let res_is_old0 = true;
        let rt_new = I::default();

        (mixed, res_old_key, res_old_value, res_is_old0, rt_new)
    };

    let mut rt_new = rt_new;
    let mut mixed = mixed;

    let key_bits = found_key.to_bits();

    let mut res_siblings = vec![];
    for (level, (&sibling, bit)) in res_find.siblings.iter().zip(key_bits).rev().enumerate() {
        let new_sibling = if level == 0 && !res_is_old0 {
            I::default()
        } else {
            sibling
        };
        let old_sibling = sibling;
        let old_node = if bit {
            Node::Internal(old_sibling, rt_old)
        } else {
            Node::Internal(rt_old, old_sibling)
        };

        rt_old = H::calc_node_hash(old_node);
        delete_keys.push(rt_old);

        if !I::default().eq(&new_sibling) {
            mixed = true;
        }

        if mixed {
            res_siblings.reverse();
            res_siblings.push(sibling);
            res_siblings.reverse();
            let new_node = if bit {
                Node::Internal(new_sibling, rt_new)
            } else {
                Node::Internal(rt_new, new_sibling)
            };
            rt_new = H::calc_node_hash(new_node.clone());
            insert_entries.push((rt_new, new_node));
        }
    }

    {
        nodes_db
            .multi_delete(&delete_keys)
            .map_err(|_| anyhow::anyhow!("fail to delete multiple entries"))?;
        nodes_db
            .multi_insert(insert_entries)
            .map_err(|_| anyhow::anyhow!("fail to insert multiple entries"))?;
        // tree: &.roots_db
        //     .set(rt_new)
        //     .map_err(|_| anyhow::anyhow!("fail to set root"))?;
        // tree: &.root = rt_new;
    }

    // original
    // Ok(SparseMerkleProcessProof {
    //     old_root: rt_old,
    //     old_key: res_old_key,
    //     old_value: res_old_value,
    //     new_root: rt_new,
    //     new_key: found_key,     // del_key
    //     new_value: found_value, // del_value
    //     siblings: res_siblings,
    //     is_old0: res_is_old0,
    //     fnc: ProcessMerkleProofRole::ProcessDelete,
    // })

    let _ = core::mem::replace(root, rt_new);

    Ok(SparseMerkleProcessProof {
        old_root: rt_old,
        old_key: found_key,     // del_key
        old_value: found_value, // del_value
        new_root: rt_new,
        new_key: res_old_key,
        new_value: res_old_value,
        siblings: res_siblings,
        is_old0: res_is_old0,
        fnc: ProcessMerkleProofRole::ProcessDelete,
    })
}

/// NOTICE: The transition from a non-zero value to a non-zero value deal with the updating process.
fn noop<K: KeyLike, V: ValueLike, I: HashLike, H: NodeHash<K, V, I>, D: NodeData<K, V, I>>(
    _nodes_db: &D,
    root: &I,
    key: &K,
) -> anyhow::Result<SparseMerkleProcessProof<K, V, I>> {
    // let res_find = find::<K, V, I, H, D>(_nodes_db, root, key)?;

    // // Given key should not be found.
    // if res_find.found {
    //     return Err(anyhow::anyhow!("given key already exists"));
    // }

    Ok(SparseMerkleProcessProof {
        old_root: *root,
        old_key: *key,
        old_value: V::default(),
        new_root: *root,
        new_key: *key,
        new_value: V::default(),
        siblings: vec![],
        is_old0: true,
        fnc: ProcessMerkleProofRole::ProcessNoOp,
    })
}

pub fn calc_process_proof<
    K: KeyLike,
    V: ValueLike,
    I: HashLike,
    H: NodeHash<K, V, I>,
    D: NodeData<K, V, I>,
>(
    nodes_db: &mut D,
    root: &mut I,
    key: K,
    value: V,
) -> anyhow::Result<SparseMerkleProcessProof<K, V, I>> {
    let res_find = find::<K, V, I, H, D>(nodes_db, root, &key)?;

    if V::default().eq(&value) {
        if res_find.found {
            remove::<K, V, I, H, D>(nodes_db, root, &key)
        } else {
            noop::<K, V, I, H, D>(nodes_db, root, &key)
        }
    } else if res_find.found {
        update::<K, V, I, H, D>(nodes_db, root, &key, value)
    } else {
        insert::<K, V, I, H, D>(nodes_db, root, key, value)
    }
}

pub(crate) fn find<
    K: KeyLike,
    V: ValueLike,
    I: HashLike,
    H: NodeHash<K, V, I>,
    D: NodeData<K, V, I>,
>(
    nodes_db: &D,
    root: &I,
    key: &K,
) -> anyhow::Result<SparseMerkleInclusionProof<K, V, I>> {
    let key_bits = key.to_bits();

    find_rec::<K, V, I, H, D>(nodes_db, root, key, &key_bits, 0)
}

fn find_rec<K: KeyLike, V: ValueLike, I: HashLike, H: NodeHash<K, V, I>, D: NodeData<K, V, I>>(
    nodes_db: &D,
    root: &I,
    key: &K,
    key_bits: &[bool],
    level: usize,
) -> anyhow::Result<SparseMerkleInclusionProof<K, V, I>> {
    if I::default().eq(root) {
        return Ok(SparseMerkleInclusionProof {
            root: *root,
            found: false,
            siblings: vec![],
            key: *key,
            value: V::default(),
            not_found_key: K::default(),
            not_found_value: V::default(),
            is_old0: true,
        });
    }

    let root_node = nodes_db
        .get(root)
        .map_err(|err| anyhow::anyhow!("fail to fetch the root node: {:?}", err))?;
    match root_node {
        Some(Node::Leaf(record_key, record_value)) => {
            if record_key.eq(key) {
                Ok(SparseMerkleInclusionProof {
                    root: *root,
                    found: true,
                    siblings: vec![],
                    key: *key,
                    value: record_value,
                    not_found_key: K::default(),
                    not_found_value: V::default(),
                    is_old0: false,
                })
            } else {
                Ok(SparseMerkleInclusionProof {
                    root: *root,
                    found: false,
                    siblings: vec![],
                    key: *key,
                    value: V::default(),
                    not_found_key: record_key,
                    not_found_value: record_value,
                    is_old0: false,
                })
            }
        }
        Some(Node::Internal(record_left, record_right)) => {
            if key_bits[level] {
                let mut res =
                    find_rec::<K, V, I, H, D>(nodes_db, &record_right, key, key_bits, level + 1)?;
                res.siblings.reverse();
                res.siblings.push(record_left);
                res.siblings.reverse();
                res.root = *root;

                Ok(res)
            } else {
                let mut res =
                    find_rec::<K, V, I, H, D>(nodes_db, &record_left, key, key_bits, level + 1)?;
                res.siblings.reverse();
                res.siblings.push(record_right);
                res.siblings.reverse();
                res.root = *root;

                Ok(res)
            }
        }
        None => Err(anyhow::anyhow!("searching node is not found")),
    }
}

pub fn calc_inclusion_proof<
    K: KeyLike,
    V: ValueLike,
    I: HashLike,
    H: NodeHash<K, V, I>,
    D: NodeData<K, V, I>,
>(
    nodes_db: &D,
    root: &I,
    key: &K,
) -> anyhow::Result<SparseMerkleInclusionProof<K, V, I>> {
    find::<K, V, I, H, D>(nodes_db, root, key)
}

pub fn get<K: KeyLike, V: ValueLike, I: HashLike, H: NodeHash<K, V, I>, D: NodeData<K, V, I>>(
    nodes_db: &D,
    root: &I,
    key: &K,
) -> anyhow::Result<V> {
    let res_find = find::<K, V, I, H, D>(nodes_db, root, key)?;

    if res_find.found {
        Ok(res_find.value)
    } else {
        Ok(V::default())
    }
}
