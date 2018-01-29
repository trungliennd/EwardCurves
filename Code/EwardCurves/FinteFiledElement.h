#include <vector>
#include <stdio.h>
#include <gmp.h>
#include <cstdlib>

namespace Cryptography {

    class FiniteFieldElement {
        public:
            mpz_t P;
            mpz_t i_;

        void assign(mpz_t j) {

            mpz_set(this->i_, j);
            // if j < 0
            if(mpz_sgn(j) == -1) {
                mpz_t r, P2;
                mpz_init(r);
                mpz_init(P2);
                // r = (j%P)
                mpz_mod(r, j, P);
                // P2 = 2*P
                mpz_mul_ui(P2, P, 2);
                // i_ = r + P2
                mpz_add(this->i_, r, P2);
                mpz_clear(r);
                mpz_clear(P2);
            }
            mpz_mod(this->i_, this->i_, P);

        }

        // Contructor no parameters
        FiniteFieldElement() {
            mpz_init(this->i_);
            mpz_init(this->P);
        }

        // Contructor have parameters
        FiniteFieldElement(mpz_t i, mpz_t P) {
            mpz_init(this->P);
            mpz_init(this->i_);
            mpz_set(this->P, P);
            assign(i);
        }

        // Copyt elements
        FiniteFieldElement(const FiniteFieldElement& ffe1){
            mpz_init(this->P);
            mpz_init(this->i_);
            mpz_set(this->P, ffe1.P);
            mpz_set(this->i_, ffe1.i_);
        }

        // return i_, P
        void i(mpz_t rs) {
            mpz_set(rs, i_);
        }

        void p(mpz_t rs) {
            mpz_set(rs, P);
        }

        void set(mpz_t i) {
            mpz_set(this->i_, i);
        }

        void negative() {
            mpz_neg(i_,i_);
            assign(i_);
        }

        void assignFiniteFieldElement(const FiniteFieldElement& ffe) {
            mpz_set(this->i_, ffe.i_);
            mpz_set(this->P, ffe.P);
        }

        void mulAssign(const FiniteFieldElement& ffe2) {
            // if ffe1.P = ffe2.P
            if(mpz_cmp(this->P, ffe2.P) == 0) {
                mpz_t rs;
                mpz_init(rs);
                mpz_mul(rs, this->i_, ffe2.i_);
                mpz_mod(this->i_, rs, ffe2.P);
            }

        }

        bool compareEqual(const FiniteFieldElement& ffe) {
            if(mpz_cmp(this->P, ffe.P) == 0) {
                if(mpz_cmp(this->i_, ffe.i_) == 0) {
                    return true;
                }
            }
            return false;
        }

        bool compareEqual(mpz_t i) {
            if(mpz_cmp(this->i_, i) == 0) {
                return true;
            }
            return false;
        }

        void divFiniteFieldElement(const FiniteFieldElement& ffe1, const FiniteFieldElement& ffe2) {
            if(mpz_cmp(ffe1.P, ffe2.P) == 0) {
                mpz_t rs;
                mpz_init(rs);
                mpz_invert(rs, ffe2.i_, ffe2.P);
                mpz_mul(rs, ffe1.i_, rs);
                mpz_set(this->P, ffe1.P);
                assign(rs);
            }else {
                mpz_init(this->i_);
                mpz_init(this->P);
            }
        }

        void addFiniteFieldElement(const FiniteFieldElement& ffe1, const FiniteFieldElement& ffe2) {
            if(mpz_cmp(ffe1.P, ffe2.P) == 0) {
                mpz_t rs;
                mpz_init(rs);
                mpz_add(rs, ffe1.i_, ffe2.i_);
                mpz_set(this->P, ffe1.P);
                assign(rs);
            }else {
                mpz_init(this->i_);
                mpz_init(this->P);
            }
        }

        void subFiniteFieldElement(const FiniteFieldElement& ffe1, const FiniteFieldElement& ffe2) {
            if(mpz_cmp(ffe1.P, ffe2.P) == 0) {
                mpz_t rs;
                mpz_init(rs);
                mpz_sub(rs, ffe1, ffe2);
                mpz_set(this->P, ffe1.P);
                assign(rs);
            }else {
                mpz_init(this->i_);
                mpz_init(this->P);
            }
        }

        void addFiniteFieldElement(const FiniteFieldElement& ffe1, mpz_t i) {
            mpz_t rs;
            mpz_init(rs);
            mpz_add(rs, ffe1.i_, i);
            mpz_set(this->P, ffe1.P);
            assign(rs);
        }

        void mulFiniteFieldElement(const FiniteFieldElement& ffe1, mpz_t i) {
            mpz_t rs;
            mpz_init(rs);
            mpz_mul(rs, ffe1.i_, i);
            mpz_set(this->P, ffe1.P);
            assign(rs);
        }

        void mulFiniteFieldElement(const FiniteFieldElement& ffe1, const FiniteFieldElement& ffe2) {
            if(mpz_cmp(ffe1.P, ffe2.P) == 0) {
                mpz_t rs;
                mpz_init(rs);
                mpz_mul(rs, ffe1.i_, ffe2.i_);
                mpz_set(this->P, ffe1.P);
                assign(rs);
            }else {
                mpz_init(this->i_);
                mpz_init(this->P);
            }
        }

       void printElement() {
            gmp_printf("%Zd",this->i_);
       }
    };


    class EdwardsCurve {
        public:
            mpz_t P;
            typedef FiniteFieldElement ffe_t;
        class Point {

        };
    };

}
