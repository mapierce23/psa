use crate::sketch;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TripleShare<T> {
    pub a: T,
    pub b: T,
    pub c: T,
}

// XXX: Optimization: compress Beaver triples.
impl<T> TripleShare<T>
where
    T: crate::Share + std::fmt::Debug,
{
    pub fn new() -> [TripleShare<T>; 2] {
        let (a_s0, a_s1) = T::share_random();
        let (b_s0, b_s1) = T::share_random();

        // c = a*b
        let mut c = a_s0.clone();
        c.add(&a_s1);

        let mut b = b_s0.clone();
        b.add(&b_s1);

        c.mul(&b);

        let (c_s0, c_s1) = c.share();

        [
            TripleShare {
                a: a_s0,
                b: b_s0,
                c: c_s0,
            },
            TripleShare {
                a: a_s1,
                b: b_s1,
                c: c_s1,
            },
        ]
    }
}

// We will compute in MPC:
//    \sum_i [ (x_i * y_i) + z_i ]
#[derive(Clone)]
pub struct MulState<T> {
    server_idx: bool,
    triples: Vec<TripleShare<T>>,

    xs: Vec<T>,
    ys: Vec<T>,
    zs: Vec<T>,

    rs: Vec<T>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorShare<T> {
    ds: Vec<T>,
    es: Vec<T>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cor<T> {
    ds: Vec<T>,
    es: Vec<T>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutShare<T> {
    share: T,
}

impl<T> MulState<T>
where
    T: crate::Share + std::cmp::PartialEq + std::fmt::Debug + From<u32>,
{
    pub fn new(
        server_idx: bool,
        triples: Vec<TripleShare<T>>,
        mac_key: &T,
        mac_key2: &T,
        val_share: &T,
        val2_share: &T,
        sketch: &sketch::SketchOutput<T>,
    ) -> MulState<T> {

        let mut out = MulState {
            server_idx,
            triples: triples,

            xs: Vec::with_capacity(sketch::TRIPLES_PER_LEVEL),
            ys: Vec::with_capacity(sketch::TRIPLES_PER_LEVEL),
            zs: Vec::with_capacity(sketch::TRIPLES_PER_LEVEL),

            rs: Vec::with_capacity(sketch::TRIPLES_PER_LEVEL),
        };

        //      <r,x><r^2,x> - beta^2 =? 0
        // =============================================
        out.xs.push(sketch.r_x.clone()); // z1
        out.ys.push(sketch.r2_x.clone()); // z2
        let mut c0 = val2_share.clone();
        c0.negate();
        out.zs.push(c0); // - beta^2
        // =============================================

        // 2) Check MAC values are correct.
        //    For linear query q, vector x, MAC key k
        //          (<q, kx> + k^2) - k^2 - k*<q,x> == 0?

        //   2a) Check that k^2 - k*k = 0
        // =============================================
        let mut mac_key2_neg = mac_key2.clone();
        mac_key2_neg.negate();

        out.xs.push(mac_key.clone());
        out.ys.push(mac_key.clone());
        out.zs.push(mac_key2_neg);
        // =============================================
        //   2b) Check k <r,x> - <r, kx> = 0
        // =============================================
        out.xs.push(sketch.r_x.clone());
        out.ys.push(mac_key.clone());
        let mut sketch_r_kx_neg = sketch.r_kx.clone();
        sketch_r_kx_neg.negate(); 
        out.zs.push(sketch_r_kx_neg);
        // =============================================
        // check value shares are correct
        // =============================================
        let mut val2_share_neg = val2_share.clone();
        val2_share_neg.negate();
        out.xs.push(val_share.clone());
        out.ys.push(val_share.clone());
        out.zs.push(val2_share_neg);
        // =============================================
        // check z1^2 - z^2w
        // =============================================
        out.xs.push(sketch.r_x.clone());
        out.ys.push(sketch.r_x.clone());
        out.zs.push(T::zero());
        let mut val_share_neg = val_share.clone();
        val_share_neg.negate();
        out.xs.push(sketch.r2_x.clone());
        out.ys.push(val_share_neg);
        out.zs.push(T::zero());
        // =============================================
        // check z1z2 - z3w
        // =============================================
        out.xs.push(sketch.r_x.clone());
        out.ys.push(sketch.r2_x.clone());
        out.zs.push(T::zero());
        let mut val_share_neg = val_share.clone();
        val_share_neg.negate();
        out.xs.push(sketch.r3_x.clone());
        out.ys.push(val_share_neg);
        out.zs.push(T::zero());
        // =============================================

        out.rs = vec![sketch.rand1.clone(), 
                    sketch.rand2.clone(), 
                    sketch.rand3.clone()];

        out
    }

    pub fn cor_share(&self) -> CorShare<T> {
        let mut out = CorShare {
            ds: Vec::with_capacity(sketch::TRIPLES_PER_LEVEL),
            es: Vec::with_capacity(sketch::TRIPLES_PER_LEVEL),
        };

        for i in 0..sketch::TRIPLES_PER_LEVEL {
            let mut d = self.xs[i].clone();
            d.sub(&self.triples[i].a);
            out.ds.push(d);

            let mut e = self.ys[i].clone();
            e.sub(&self.triples[i].b);
            out.es.push(e);
        }

        out
    }

    pub fn cor(share0: &CorShare<T>, share1: &CorShare<T>) -> Cor<T> {
        let mut out = Cor {
            ds: Vec::with_capacity(sketch::TRIPLES_PER_LEVEL),
            es: Vec::with_capacity(sketch::TRIPLES_PER_LEVEL),
        };

        for i in 0..sketch::TRIPLES_PER_LEVEL {
            let mut d = T::zero();
            d.add(&share0.ds[i]);
            d.add(&share1.ds[i]);
            out.ds.push(d);

            let mut e = T::zero();
            e.add(&share0.es[i]);
            e.add(&share1.es[i]);
            out.es.push(e);
        }

        out
    }

    pub fn out_share(&self, cor: &Cor<T>) -> OutShare<T> {
        let mut out = T::zero();
        for i in 0..sketch::TRIPLES_PER_LEVEL {
            let mut term = T::zero();
            // Compute
            // d*e/2 + d*b_i + e*a_i + c_i + z_i
            if self.server_idx {
                // Add in d*e to first share only
                let mut tmp = cor.ds[i].clone();
                tmp.mul_lazy(&cor.es[i]);

                term.add_lazy(&tmp);
            }

            let mut tmp = cor.ds[i].clone();
            tmp.mul_lazy(&self.triples[i].b);
            term.add_lazy(&tmp);

            tmp = cor.es[i].clone();
            tmp.mul_lazy(&self.triples[i].a);
            term.add_lazy(&tmp);

            term.add_lazy(&self.triples[i].c);

            term.add_lazy(&self.zs[i]);
            // term.mul_lazy(&self.rs[i]);
            out.add_lazy(&term);
        }

        out.reduce();
        OutShare { share: out }
    }

    pub fn verify(out0: &OutShare<T>, out1: &OutShare<T>) -> bool {
        let mut val = out0.share.clone();
        val.add(&out1.share);

        val == T::zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldElm;
    use crate::Group;

    #[test]
    fn triple() {
        let [t0, t1] = TripleShare::<FieldElm>::new();

        debug_assert!(t0.a != FieldElm::zero());
        debug_assert!(t0.b != FieldElm::zero());
        debug_assert!(t0.c != FieldElm::zero());

        let mut a = t0.a.clone();
        a.add(&t1.a);

        let mut b = t0.b.clone();
        b.add(&t1.b);

        let mut c = t0.c.clone();
        c.add(&t1.c);

        let mut ab = a.clone();
        ab.mul(&b);

        assert_eq!(ab, c);
    }
}
