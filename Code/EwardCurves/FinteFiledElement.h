#include <vector>
#include <time.h>
#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <cstdlib>
#include "EwardCurves.h"

using namespace std;

namespace Cryptography {
    // Cac ham cua chuong trinh
    void crypto_encode_ed225519_ClampC(unsigned char encode[], mpz_t &num_encode, unsigned int bytes);
    void crypto_decode_ed225519_ClampC(unsigned char decode[], mpz_t &num_decode, unsigned int bytes);
    void crypto_sign_ed25519_keypair(unsigned char publicKey[], unsigned char secretKey[],unsigned int bytes);
    /*
        Hang so cua chuong trinh
    */
    const unsigned int crypto_sign_ed25519_PUBLICKEYBYTES = 32;
    const unsigned int crypto_sign_ed25519_SECRETKEYBYTES = 32;

    void str_copy(unsigned char des[], unsigned char src[], int len) {
        for(int i = 0;i < len;i++) {
            des[i] = src[i];
        }
        des[len] = '\0';
    }

    unsigned long randomSeed() {
        bool check = true;
        unsigned long rand1,rand2;
        while(check) {
            time_t t1;
            srand((unsigned)time(&t1));
            rand1 = abs(rand());
            time_t t2;
            srand((unsigned)time(&t2));
            rand2 = abs(rand());
            if(rand1 == rand2) continue;
            check = false;
        }
        rand1 = rand1 << (sizeof(int) * 8);
        unsigned long randRS = (rand1 | rand2);
        return randRS;
    }

    void randomNumber(mpz_t rs,int bits) {
            unsigned long seed = randomSeed();
            gmp_randstate_t r_state;
            mpz_init(rs);
            gmp_randinit_default(r_state);
            gmp_randseed_ui(r_state, seed);
            mpz_urandomb(rs,r_state,bits);
            gmp_randclear(r_state);
    }




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

        void assignFiniteFieldElement(mpz_t i, mpz_t p) {
            mpz_set(this->P, p);
            assign(i);
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
            gmp_printf("\n%Zd\n",this->i_);
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
                    mpz_set(this->P, ec.P);
                    this->ec = &ec;
                }

                Point(const ffe_t& x,const ffe_t& y,EdwardsCurve& ec): x_(x), y_(y), ec(&ec) {
                    mpz_set(this->P, x.P);
                }

                Point(Point& e) {
                    x_.assignFiniteFieldElement(e.x());
                    y_.assignFiniteFieldElement(e.y());
                    mpz_set(this->P, e.P);
                    ec = e.ec;
              //      ec.printEd25519();
                }


                void assignPoint(const Point &rp) {
                    x_.assignFiniteFieldElement(rp.x_);
                    y_.assignFiniteFieldElement(rp.y_);
                    mpz_set(this->P, rp.P);
                    ec = rp.ec;
                }

                void assignPoint(ffe_t x, ffe_t y, mpz_t P, EdwardsCurve &e) {
                    x_.assignFiniteFieldElement(x);
                    y_.assignFiniteFieldElement(y);
                    mpz_set(this->P, P);
                    ec = &e;
                }

                // operation add (x1, y1) + (x2, y2) on Edwards Curve
                // a*x^2 + y^2 = 1 + dx^2y^2
                // is compelete if a is a square in k and d is a nonsquare in k
                // P # Q
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

                    // Free the space occupied
                    mpz_clear(ZERO);
                    mpz_clear(ONE);
                    mpz_clear(neg);
                }
                    // P # Q
                 void add(ffe_t x1, ffe_t y1, ffe_t x2, ffe_t y2) {

                    mpz_t ZERO,ONE;
                    mpz_init(ZERO);
                    mpz_init(ONE);
                    mpz_set_str(ONE,"1",10);
                    // (0, 1) + (x2, y2)
                    if(x1.compareEqual(ZERO) && y1.compareEqual(ONE)) {
                        x_.assignFiniteFieldElement(x2);
                        y_.assignFiniteFieldElement(y2);
                        mpz_set(P, x1.P);
                        return;
                    }
                    // (x1, y1) + (0, 1)
                    if(x2.compareEqual(ZERO) && y2.compareEqual(ONE)) {
                        x_.assignFiniteFieldElement(x1);
                        y_.assignFiniteFieldElement(y1);
                        mpz_set(P, x2.P);
                        return;
                    }

                    // (x1, y1) + (x1, -y1) hay P + (-P) = (0, 1)
                    mpz_t neg;
                    mpz_init(neg);
                    x2.negative(neg);
                    if(x1.compareEqual(neg) && y1.compareEqual(y2)){
                        x_.init(ZERO,this->P);
                        y_.init(ONE,this->P);
                        mpz_set(P, x1.P);
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

                    x_.divFiniteFieldElement(x3_temp2, x3_temp4);

                    // y3 = (y1*y2 - a*x1*x2)/(1 - d*x1*x2*y1*y2)
                    ffe_t y3_temp,y3_temp1,y3_temp2,y3_temp3;
                    y3_temp.mulFiniteFieldElement(y1,y2); // y1*y2
                    y3_temp1.mulFiniteFieldElement(x1,x2); // x1*x2;
                    y3_temp1.mulFiniteFieldElement(y3_temp1, ec->a()); // a*x1*x2;
                    y3_temp2.subFiniteFieldElement(y3_temp, y3_temp1); // y1*y2 - a*x1*x2;
                    y3_temp3.subFiniteFieldElement(ONE, x3_temp3); // 1 - d*x1*x2*y1*y2;
                    y_.divFiniteFieldElement(y3_temp2, y3_temp3);
                    mpz_set(P, x1.P);

                    // Free the space occupied
                    mpz_clear(ZERO);
                    mpz_clear(ONE);
                    mpz_clear(neg);
                }

                void doubling(ffe_t x, ffe_t y, ffe_t xR, ffe_t yR) {

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

                    // Free the space occupied
                    mpz_clear(ZERO);
                    mpz_clear(ONE);
                    mpz_clear(TWO);
                }

                void doubling(ffe_t x, ffe_t y) {

                    mpz_t ZERO,ONE,TWO;
                    mpz_init(ZERO);
                    mpz_init(ONE);
                    mpz_init(TWO);
                    mpz_set_str(ONE, "1", 10);
                    mpz_set_str(TWO, "2", 10);
                    // (0, 1)*(0, 1)
                   if(x.compareEqual(ZERO) && y.compareEqual(ONE)) {

                         mpz_set(P, x.P);
                        x_.init(ZERO,this->P);
                        y_.init(ONE,this->P);
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
                    x_.divFiniteFieldElement(x3_temp, x3_temp3);

                    // formula 2[P] y = (y^2 - a*x^2)/(2 - a*x^2 - y^2)
                    y3_temp.subFiniteFieldElement(x3_temp2, x3_temp1);  // (y^2 - a*x^2)
                    y3_temp2.addFiniteFieldElement(x3_temp1, x3_temp2); // (a*x^2 + y^2)
                    y3_temp2.subFiniteFieldElement(TWO, y3_temp2); // (2 - a*x^2 + y^2);
                    y_.divFiniteFieldElement(y3_temp, y3_temp2);
                    mpz_set(P, x.P);
                    // Free the space occupied
                    mpz_clear(ZERO);
                    mpz_clear(ONE);
                    mpz_clear(TWO);
                }

                // add double return (2^m) mod P
                void addDouble(mpz_t m,Point &ace) {
                    mpz_t ZERO,ONE,i;
                    mpz_init(ZERO);
                    mpz_init(ONE);
                    mpz_init(i);
                    mpz_set_str(ZERO, "0", 10);
                    mpz_set_str(ONE, "1", 10);
                    mpz_set(i, ZERO);
                    int rs = mpz_cmp(m,ZERO);
                    if(rs > 0) {
                        Point r;
                        r.assignPoint(ace);
                        int cmp = mpz_cmp(m,i);
                        while(cmp > 0) {
                          //  gmp_printf("\n%Zd",i);
                            r.doubling(r.x_,r.y_);
                            mpz_add(i,i,ONE);
                            cmp = mpz_cmp(m,i);
                        }
                        ace.assignPoint(r);
                    }
                    // Free the space occupied
                    mpz_clear(ZERO);
                    mpz_clear(ONE);
                    mpz_clear(i);
                }

                // scalar Point
                void scalarMultiply(mpz_t k,const Point &a) {
                    Point acc;
                    acc.assignPoint(a);
                    mpz_t ZERO, i, j, b, ONE, TWO;
                    mpz_init(ZERO);
                    mpz_init(ONE);
                    mpz_set_str(ONE, "1", 10);
                    mpz_init(TWO);
                    mpz_set_str(TWO, "2", 10);
                    mpz_init(i);
                    mpz_init(j);
                    mpz_init(b);
                    Point res;
                    res.assignPoint(a);
                    res.setX(ZERO);
                    res.setY(ONE);
                    mpz_set(b, k);
                    int check = mpz_cmp(b, ZERO);
                    while(check > 0) {
                        mpz_t rs;
                        mpz_init(rs);
                        mpz_and(rs, b, ONE);
                        int check_even_odd = mpz_cmp(rs, ZERO);
                        if(check_even_odd != 0) {
                            mpz_sub(rs, i, j);
                            addDouble(rs, acc);
                            res.add(acc.x_, acc.y_, res.x_, res.y_);
                            mpz_set(j , i);
                        }
                        mpz_fdiv_q(b, b, TWO);
                        mpz_add(i, i , ONE);
                        check = mpz_cmp(b, ZERO);
                        mpz_clear(rs);
                    }

                    assignPoint(res);
                    // Free the space occupied
                    mpz_clear(ZERO);
                    mpz_clear(ONE);
                    mpz_clear(i);
                    mpz_clear(j);
                    mpz_clear(TWO);
                    mpz_clear(b);
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
                    mpz_add(temp, x1.i_, y1.i_);
                    mpz_add(temp1, x2.i_, y2.i_);
                    mpz_mul(temp, temp, temp1);
                    mpz_sub(temp, temp, C);
                    mpz_sub(temp, temp, D);
                    mpz_mul(temp, temp, F);
                    mpz_mul(X3, temp, A);

                    // Y3 = A * G * (D - a*C)
                    mpz_mul(temp, (ec->a()).i_, C);
                    mpz_sub(temp, D, temp);
                    mpz_mul(temp, temp, G);
                    mpz_mul(Y3, temp, A);

                    // Z3 = F*G
                    mpz_mul(Z3, F, G);
                    // Free the space occupied
                    mpz_clear(A);
                    mpz_clear(B);
                    mpz_clear(C);
                    mpz_clear(D);
                    mpz_clear(E);
                    mpz_clear(F);
                    mpz_clear(G);
                    mpz_clear(temp);
                    mpz_clear(temp1);
                }

                void doublingProjectCoordinates(ffe_t x1, ffe_t y1, ffe_t x2, ffe_t y2, ffe_t xR, ffe_t yR) {

                    mpz_t B,C,D,E,F,H,J,X3,Y3,Z3,temp,TWO;
                    mpz_init(B);
                    mpz_init(C);
                    mpz_init(D);
                    mpz_init(E);
                    mpz_init(F);
                    mpz_init(H);
                    mpz_init(J);
                    mpz_init(X3);
                    mpz_init(Y3);
                    mpz_init(Z3);
                    mpz_init(temp);
                    mpz_init(TWO);
                    mpz_set_str(TWO, "2", 10);

                    mpz_add(B, x1.i_, y1.i_);
                    mpz_mul(B, B, B); // (X1 + Y1)^2
                    mpz_mul(C, x1.i_, x1.i_); // X1^2
                    mpz_mul(D, y1.i_, y1.i_); // Y1^2
                    mpz_mul(E, (ec->a()).i_, D); //aC
                    mpz_add(F, E, D); // F = E + D
                    mpz_mul(H, x1.P, x1.P); // H = Z1^2
                    mpz_mul(temp, TWO, H);
                    mpz_sub(J, F ,temp); // J = F - 2*H
                    mpz_add(temp, C, D);
                    mpz_sub(temp , B, temp);
                    mpz_mul(X3, temp, J); // X3 = (B - C - D)*J

                    mpz_sub(temp, E, D);
                    mpz_mul(Y3, temp, F); // Y3 = F*(E - D);

                    mpz_mul(Z3, F, J); // Z3 = F * J

                    // Free the space occupied
                    mpz_clear(B);
                    mpz_clear(C);
                    mpz_clear(D);
                    mpz_clear(E);
                    mpz_clear(F);
                    mpz_clear(H);
                    mpz_clear(J);
                    mpz_clear(temp);
                    mpz_clear(TWO);
                }

                void printPoint() {
                    gmp_printf("x = %Zd\n", this->x_.i_);
                    gmp_printf("y = %Zd\n", this->y_.i_);
                }

                FiniteFieldElement x() const {
                    return this->x_;
                }

                void setX(mpz_t x) {
                    mpz_set(this->x_.i_, x);
                }


                FiniteFieldElement y() const {
                    return this->y_;
                }

                void setY(mpz_t y) {
                    mpz_set(y_.i_, y);
                }

        };

        // Edwards Curves implements
        typedef EdwardsCurve this_t;
        typedef class EdwardsCurve::Point point_t;

        // return a
        FiniteFieldElement a() const {
            return a_;
        }

        FiniteFieldElement d() const {
            return d_;
        }

        // equation twist curves Ewards
        // a*x^2 + y^2 = 1 + d*x^2*y^2;


        bool checkPoint(ffe_t x, ffe_t y) {
            ffe_t xx, yy,temp1, temp2;
            mpz_t ONE;
            mpz_init(ONE);
            mpz_set_str(ONE, "1", 10);
            xx.mulFiniteFieldElement(x,x);
            yy.mulFiniteFieldElement(y,y);
            temp1.mulFiniteFieldElement(xx, this->a_);
            temp1.addFiniteFieldElement(temp1, yy);
            temp2.mulFiniteFieldElement(xx,yy);
            temp2.mulFiniteFieldElement(temp2, this->d_);
            temp2.addFiniteFieldElement(temp2, ONE);
            if(temp1.compareEqual(temp2)) {
                return true;
            }
            return false;
        }

        void Degree(mpz_t rs) {
            mpz_set(rs, this->P);
        }

        void setGenerator(const Point& gx) {
            this->Gx.assignPoint(gx);
        }

        void setGenerator(ffe_t x, ffe_t y, mpz_t p, EdwardsCurve &a) {
            this->Gx.assignPoint(x, y, p, a);
        }

        void setParamester(ffe_t a, ffe_t d) {
            this->a_.assignFiniteFieldElement(a);
            this->d_.assignFiniteFieldElement(d);
        }

        //constructors
        EdwardsCurve(mpz_t p) {
            mpz_init(this->P);
            mpz_set(this->P, p);
        }

        EdwardsCurve() {
            mpz_init(this->P);
        }
       // EdwardsCurve* returnSelft() {
        //    return this;
        //}

        Point &returnGx() {
            return Gx;
        }
        void printEd25519() {
            printf("\n-------------------- Twist Edwards --------------------");
            gmp_printf("\n%Zd*x^2 + y^2 = 1 + %Zd*x^2*y^2",this->a_.i_, this->d_.i_);
            gmp_printf("\nFields p is: %Zd", this->P);
            gmp_printf("\nPoint Generator G(x, y) is: \n");
            this->Gx.printPoint();
        }

        private:
            FiniteFieldElement a_; // tham so a cua duong cong
            FiniteFieldElement d_; // tham so d cuar duong cong
            Point Gx;
         //   typedef vector<Point> table_t;
          //  table_t m_table_t;     // chua cac diem cua duong cong
          //  bool table_filled;      // neu bang da tinh

    };
    /*
    *
    * Curve25519 is defined by the following equation:
            v^2 = u^3 + 486662*u^2 + u
      Montgomery curves
            B*v^2 = u^3 + A*u^2 + u
      Twist Ewards curves
            a*x^2 + y^2 = 1 + d*x^2*y^2 with a = (A + 2)/B and d = (A - 2)/B
    *
    */

     /*
      *
        point generator G(x,y)
            x = 547c4350219f5e19dd26a3d6668b74346a8eb726eb2396e1228cfa397ffe6bd4
            y = 6666666666666666666666666666666666666666666666666666666666666658

        Finite Fp
            p = 2^255 - 19 = 57896044618658097711785492504343953926634992332820282019728792003956564819949

        paramester
            a = 486664 and d = 486660

      */
      typedef EdwardsCurve ed25519;
      typedef FiniteFieldElement ffe_t;
      ed25519 *Ed_curves25519;
      //mpz_t scret_key;

    /*
    * init curves 25519 Twist Edwards
    */
      void initCurveTwistEwards25519() {
        mpz_t p,gx,gy,a,d;
        mpz_init(p);
        mpz_init(gx);
        mpz_init(gy);
        mpz_init(a);
        mpz_init(d);
        mpz_set_str(p, "57896044618658097711785492504343953926634992332820282019728792003956564819949", 10);
        mpz_set_str(gx, "547c4350219f5e19dd26a3d6668b74346a8eb726eb2396e1228cfa397ffe6bd4", 16);
        mpz_set_str(gy, "6666666666666666666666666666666666666666666666666666666666666658", 16);
        mpz_set_str(a, "486664", 10);
        mpz_set_str(d, "486660", 10);
        ffe_t fgx(gx, p);
        ffe_t fgy(gy, p);
        ffe_t fa(a, p);
        ffe_t fd(d, p);
        Ed_curves25519 = new ed25519(p);
        Ed_curves25519->setGenerator(fgx, fgy, p, *Ed_curves25519);
        Ed_curves25519->setParamester(fa,fd);
        bool check = Ed_curves25519->checkPoint(fgx,fgy);
        if(check) printf("\nCurves is createds");
        Ed_curves25519->printEd25519();
      }

      void crypto_sign_ed25519_keypair(unsigned char publicKey[], unsigned char secretKey[],unsigned int bytes) {
        mpz_t n;
        mpz_init(n);
        randomNumber(n, 255);
        crypto_encode_ed225519_ClampC(secretKey, n, bytes);
        // public key n*G(x,y)
        ed25519::Point q;
        q.scalarMultiply(n, Ed_curves25519->returnGx());
        crypto_encode_ed225519_ClampC(publicKey, q.x_.i_, bytes);
      }

      void crypto_encode_ed225519_ClampC(unsigned char encode[], mpz_t &num_encode, unsigned int bytes) {
         mpz_t q, r, t;
         mpz_init(q);
         mpz_init(r);
         mpz_init(t);
         // 1 byte = 8 bits
         unsigned int bits = bytes << 3;
         char t_char[bytes];
         itoa(bits, t_char, 10);
         mpz_set_str(t, t_char, 10);
         mpz_set(q, num_encode);
         for(int i = 0;i < bytes;i++) {
            mpz_fdiv_qr(q, r, q, t);
            encode[i] = (unsigned char) mpz_get_ui(r);
         }
         // free memory
         mpz_clear(q);
         mpz_clear(r);
         mpz_clear(t);
      }

      void crypto_decode_ed225519_ClampC(unsigned char decode[], mpz_t &num_decode, unsigned int bytes) {
        mpz_t t;
        mpz_init(t);
        unsigned int bits = bytes << 3;
        char t_char[bytes];
        itoa(bits, t_char, 10);
        mpz_set_str(t, t_char, 10);
        unsigned char temp[bytes];
        str_copy(temp, decode, bytes);
        for(int i = 0; i < bytes;i++) {
            mpz_t t1,t2;
            mpz_init(t1);
            mpz_init(t2);
            char tempp[2];
            itoa((unsigned int) temp[i], tempp, 16);
            mpz_set_str(t1, tempp, 16);
            mpz_pow_ui(t2, t, i);
            mpz_mul(t1, t1, t2);
            mpz_add(num_decode, num_decode, t1);
            mpz_clear(t1);
            mpz_clear(t2);
        }
        mpz_clear(t);
      }

      // ham print khoa
      void printKey(unsigned char keys[], unsigned int bytes) {
        printf("\nKey is: \n");
        for(int i = 0;i < bytes;i++) {
            if((i != 0) && ((i % 8) == 0)) {
                printf("\n");
            }
            printf("x%x\t", keys[i]);
        }
        printf("\n");
      }

      // test
      void test() {
        mpz_t n,z;
        mpz_init(n);
        mpz_init(z);
       // mpz_set_str(n, "4096",10);
        randomNumber(n, 255);
      //  mpz_set_str(n,"4098",10);
        gmp_printf("\nN is: %Zd\n", n);
        unsigned char encode[32];
        crypto_encode_ed225519_ClampC(encode, n, 32);
        for(int i = 0;i < 32;i++) {
            if((i!= 0) && (i % 8 == 0)) {
                printf("\n");
            }
            printf("x%x\t", encode[i]);
        }
        printf("\n");
        crypto_decode_ed225519_ClampC(encode, z, 32);
        gmp_printf("\nN is: %Zd\n", z);
     //  crypto_decode_ed225519_ClampC(encode, z, 32)
      }


}
