// Copied from here: https://users.rust-lang.org/t/rayon-and-join-for-multiple-results/86935/11

#[doc(hidden)]
pub use rayon as __rayon_reexport;

// might improve error message on type error
#[doc(hidden)]
pub fn __requires_sendable_closure<R, F: FnOnce() -> R + Send>(x: F) -> F {
    x
}

#[macro_export]
#[doc(hidden)]
macro_rules! __join_implementation {
    ($len:expr; $($f:ident $r:ident $a:expr),*; $b:expr, $($c:expr,)*) => {
        $crate::__join_implementation!{$len + 1; $($f $r $a,)* f r $b; $($c,)* }
    };
    ($len:expr; $($f:ident $r:ident $a:expr),* ;) => {
        match ($(Some($crate::join_macro::__requires_sendable_closure($a)),)*) {
            ($(mut $f,)*) => {
                $(let mut $r = None;)*
                let array: [&mut (dyn FnMut() + Send); $len] = [
                    $(&mut || $r = Some((&mut $f).take().unwrap()())),*
                ];
                $crate::join_macro::__rayon_reexport::iter::ParallelIterator::for_each(
                    $crate::join_macro::__rayon_reexport::iter::IntoParallelIterator::into_par_iter(array),
                    |f| f(),
                );
                ($($r.unwrap(),)*)
            }
        }
    };
}

#[macro_export]
macro_rules! join {
    ($($($a:expr),+$(,)?)?) => {
        $crate::__join_implementation!{0;;$($($a,)+)?}
    };
}
