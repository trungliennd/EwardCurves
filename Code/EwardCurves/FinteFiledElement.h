#include <vector>
#include <stdio.h>
#include <gmp.h>
#include <cstdlib>
using namespace std;

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

        void init() {
            mpz_init(this->i_);
            mpz_init(this->P);
        }

        void init(mpz_t i, mpz_t p) {
            mpz_set(this->P, p);
            assign(i);
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

        ~FiniteFieldElement() {
            mpz_clear(this->i_);
            mpz_clear(this->P);
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

        void negative(mpz_t i){
            mpz_neg(i,i_);
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

        bool compareEqual(mpz_t& i) {
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
                mpz_sub(rs, ffe1.i_, ffe2.i_);
                mpz_set(this->P, ffe1.P);
                assign(rs);
            }else {
                mpz_init(this->i_);
                mpz_init(this->P);
            }
        }

        void subFiniteFieldElement(mpz_t& a, const FiniteFieldElement& ffe) {
            mpz_t rs;
            mpz_init(rs);
            mpz_sub(rs, a, ffe.i_);
            mpz_set(this->P, ffe.P);
            assign(rs);
        }

        void addFiniteFieldElement(const FiniteFieldElement& ffe1, mpz_t& i) {
            mpz_t rs;
            mpz_init(rs);
            mpz_add(rs, ffe1.i_, i);
            mpz_set(this->P, ffe1.P);
            assign(rs);
        }

        void mulFiniteFieldElement(const FiniteFieldElement& ffe1, mpz_t& i) {
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
            public:
                mpz_t P;
                friend class EdwardsCurve;
                typedef FiniteFieldElement ffe_t;
                ffe_t x_;  // coordinates x
                ffe_t y_;  // coordinates y
                EdwardsCurve *ec;
                // constructor point
                Point(): x_(), y_(), ec(0) {
                    mpz_init(P);
                }

                Point(mpz_t x, mpz_t y, mpz_t s): x_(x, s), y_(y, s), ec(0) {
                    mpz_init(P);
                    mpz_set(P, s);
                }

                Point(const ffe_t& x, const ffe_t& y): x_(x), y_(y), ec(0) {
                    mpz_init(P);
                    mpz_set(this->P, x.P);
                }

                Point(mpz_t x, mpz_t y, EdwardsCurve& ec) {
                    mpz_t rs;
                    mpz_init(rs);
                    ec.Degree(rs);
                    x_.init(x, rs);
                    y_.init(y, rs);
                    this->ec = &ec;
                }

                Point(const ffe_t& x,const ffe_t& y,EdwardsCurve& ec): x_(x), y_(y), ec(&ec) {
                    mpz_set(this->P, x.P);
                }

                Point(const Point& e) {
                    x_.assignFiniteFieldElement(e.x_);
                    y_.assignFiniteFieldElement(e.y_);
                    mpz_set(this->P, e.P);
                    ec = e.ec;
                }


                // operation add (x1, y1) + (x2, y2) on Edwards Curve
                // a*x^2 + y^2 = 1 + dx^2y^2
                // is compelete if a is a square in k and d is a nonsquare in k
                void add(ffe_t x1, ffe_t y1, ffe_t x2, ffe_t y2, ffe_t xR, ffe_t yR) {
                    mpz_t ZERO,ONE;
                    mpz_init(ZERO);
                    mpz_init(ONE);
                    mpz_set_str(ONE,"1",10);
                    // (0, 1) + (x2, y2)
                    if(x1.compareEqual(ZERO) && y1.compareEqual(ONE)) {
                        xR.assignFiniteFieldElement(x2);
                        yR.assignFiniteFieldElement(y2);
                        return;
                    }
                    // (x1, y1) + (0, 1)
                    if(x2.compareEqual(ZERO) && y2.compareEqual(ONE)) {
                        xR.assignFiniteFieldElement(x1);
                        yR.assignFiniteFieldElement(y1);
                        return;
                    }

                    // (x1, y1) + (x1, -y1) hay P + (-P) = (0, 1)
                    mpz_t neg;
                    mpz_init(neg);
                    x2.negative(neg);
                    if(x1.compareEqual(neg) && y1.compareEqual(y2)){
                        xR.init(ZERO,this->P);
                        yR.init(ONE,this->P);
                        return;
                    }

                    // add (x1, y1) + (x2, y2) = (x3, y3)
                    // x3 = (x1*y2 + y1*x2)/(1 + d*x1*x2*y1*y2)
                    // (x1*y2 + y1*x2)
                    ffe_t x3_temp,x3_temp1,x3_temp2,x3_temp3,x3_temp4;
                    x3_temp.mulFiniteFieldElement(x1,y2); // x1*y2
                    x3_temp1.mulFiniteFieldElement(y1,x2); // y1*x2
                    x3_temp2.addFiniteFieldElement(x3_temp, x3_temp1); // x1*y2 + y1*x2
                    x3_temp3.mulFiniteFieldElement(x3_temp,x3_temp1); // x1*x2*y1*y2
                    x3_temp3.mulFiniteFieldElement(x3_temp3,ec->d()); //x1*x2*y1*y2*d
                    x3_temp4.addFiniteFieldElement(x3_temp3, ONE); //x1*x2*y1*y2*d + 1

                    xR.divFiniteFieldElement(x3_temp2, x3_temp4);

                    // y3 = (y1*y2 - a*x1*x2)/(1 - d*x1*x2*y1*y2)
                    ffe_t y3_temp,y3_temp1,y3_temp2,y3_temp3;
                    y3_temp.mulFiniteFieldElement(y1,y2); // y1*y2
                    y3_temp1.mulFiniteFieldElement(x1,x2); // x1*x2;
                    y3_temp1.mulFiniteFieldElement(y3_temp1, ec->a()); // a*x1*x2;
                    y3_temp2.subFiniteFieldElement(y3_temp, y3_temp1); // y1*y2 - a*x1*x2;
                    y3_temp3.subFiniteFieldElement(ONE, x3_temp3); // 1 - d*x1*x2*y1*y2;
                    yR.divFiniteFieldElement(y3_temp2, y3_temp3);
                }

                void Doubling(ffe_t x, ffe_t y, ffe_t xR, ffe_t yR) {

                    mpz_t ZERO,ONE,TWO;
                    mpz_init(ZERO);
                    mpz_init(ONE);
                    mpz_init(TWO);
                    mpz_set_str(ONE, "1", 10);
                    mpz_set_str(TWO, "2", 10);
                    // (0, 1)*(0, 1)
                    if(x.compareEqual(ZERO) && y.compareEqual(ONE)) {
                        xR.init(ZERO,this->P);
                        yR.init(ONE,this->P);
                        return;
                    }

                    // formula 2[P] x = 2*x1*y1/(a*x1^2 + y1^2);
                    ffe_t x3_temp,x3_temp1,x3_temp2,x3_temp3,y3_temp,y3_temp2;
                    x3_temp.mulFiniteFieldElement(x, y); // x*y
                    x3_temp.mulFiniteFieldElement(x3_temp, TWO); // 2*x*y
                    x3_temp1.mulFiniteFieldElement(x, x);  // x^2
                    x3_temp1.mulFiniteFieldElement(x3_temp1, ec->a()); // a*x^2;
                    x3_temp2.mulFiniteFieldElement(y, y); // y^2
                    x3_temp3.addFiniteFieldElement(x3_temp1, x3_temp2); // a*x^2 + y^2;
                    xR.divFiniteFieldElement(x3_temp, x3_temp3);

                    // formula 2[P] y = (y^2 - a*x^2)/(2 - a*x^2 - y^2)
                    y3_temp.subFiniteFieldElement(x3_temp2, x3_temp1);  // (y^2 - a*x^2)
                    y3_temp2.addFiniteFieldElement(x3_temp1, x3_temp2); // (a*x^2 + y^2)
                    y3_temp2.subFiniteFieldElement(TWO, y3_temp2); // (2 - a*x^2 + y^2);
                    yR.divFiniteFieldElement(y3_temp, y3_temp2);

                }


                // (X^2 + aY2)Z^2 = Z^4 + dX^2Y^2.
                // projective coordinates
                void addProjectCoordinates(ffe_t x1, ffe_t y1, ffe_t x2, ffe_t y2, ffe_t xR, ffe_t yR) {

                    mpz_t A,B,C,D,E,F,G,X3,Y3,Z3,temp,temp1;
                    mpz_init(A);
                    mpz_init(B);
                    mpz_init(C);
                    mpz_init(D);
                    mpz_init(E);
                    mpz_init(F);
                    mpz_init(G);
                    mpz_init(X3);
                    mpz_init(Y3);
                    mpz_init(Z3);
                    mpz_init(temp);
                    mpz_init(temp1);

                    mpz_mul(A, x1.P, x2.P); // A = Z1 * Z2
                    mpz_mul(B, (ec->d()).i_, A); // d*A
                    mpz_mul(B, B, A); // B = d*A^2
                    mpz_mul(C, x1.i_, x2.i_); // C = X1* X2
                    mpz_mul(D, y1.i_, y2.i_); // D = y1 * Y2
                    mpz_mul(E, (ec->d()).i_, C);
                    mpz_mul(E, E, D); // E = dC*D;
                    mpz_sub(F, B, E); // F = B - E;
                    mpz_add(G, B, E); // G = B + E;
                    // X3 = A * F *((X1 + Y1)*(X2 + Y2) - C - D)
                    mpz_add(temp, X1.i_, Y1.i_);
                    mpz_add(temp1, X2.i_, Y2.i_);
                    mpz_mul(temp, temp, temp1);
                    mpz_sub(temp, temp, C);
                    mpz_sub(temp, temp, D);
                    mpz_mul(temp, temp, F);
                    mpz_mul(X3, temp, A);
                    // Y3 = A * G * (D - a*C)

                    mpz_mul(temp, (ec->a()).i_, C);
                    mpz_sub(temp, D, temp);
                    mpz_mul(temp, temp, G);



                }

        };

        // Edwards Curves thuc hien
        typedef EdwardsCurve this_t;
        typedef class EdwardsCurve::Point point_t;

        // return a
        FiniteFieldElement a() const {
            return a_;
        }

        FiniteFieldElement d() const {
            return d_;
        }

        private:
            FiniteFieldElement a_; // tham so a cua duong cong
            FiniteFieldElement d_; // tham so d cuar duong cong
            typedef vector<Point> table_t;
            table_t m_table_t;     // chua cac diem cua duong cong
            bool table_filled;      // neu bang da tinh

        void Degree(mpz_t rs) {
            mpz_set(rs, this->P);
        }

    };

}
