use super::node_data::Node;

pub trait NodeHash<K: Sized, V: Sized, I: Sized> {
    fn calc_node_hash(node: Node<K, V, I>) -> I;
}
