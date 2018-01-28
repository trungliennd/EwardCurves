#include<iostream>
#include<ostream>
#include <vector>
#include <NTL/ZZ.h>
#include <cstdlib>
using namespace std;
using namespace NTL;

namespace Cryptography {

    int EGCD(int a, int b, int& u, int &v)
            {
                u = 1;
                v = 0;
                int g = a;
                int u1 = 0;
                int v1 = 1;
                int g1 = b;
                while (g1 != 0)
                {
                    int q = g/g1; // Integer divide
                    int t1 = u - q*u1;
                    int t2 = v - q*v1;
                    int t3 = g - q*g1;
                    u = u1; v = v1; g = g1;
                    u1 = t1; v1 = t2; g1 = t3;
                }

                return g;
            }

            int InvMod(int x, int n) // Solve linear congruence equation x * z == 1 (mod n) for z
            {
                //n = Abs(n);
                x = x % n; // % is the remainder function, 0 <= x % n < |n|
                int u,v,g,z;
                g = EGCD(x, n, u,v);
                if (g != 1)
                {
                    // x and n have to be relative prime for there to exist an x^-1 mod n
                    z = 0;
                }
                else
                {
                    z = u % n;
                }
                return z;
            }


    template<int P> class FiniteFieldElement {
        int i_;

        void assign (int j) {
            i_ = j;
            if(j < 0) {
                i_ = (j%P) + 2*P;
            }

            i_ %= P;
        }

        public:
            // Contructor
            FiniteFieldElement(): i_(0){}
            // contructor
            explicit FiniteFieldElement(int i) {
                assign(i);
            }
            // Copy
            FiniteFieldElement(const FiniteFieldElement<P>& ffe1): i_(ffe1.i_) {}

            int i() const {
                return i_;
            }

            // - FiniteFieldElement

            FiniteFieldElement operator-() const {
                return FiniteFieldElement(-i_);
            }

            FiniteFieldElement& operator=(int i) {
                assign(i);
                return *this;
            }

            FiniteFieldElement<P>& operator=(const FiniteFieldElement<P>& ffe1) {
                i_ = ffe1.i_;
                return *this;
            }

            FiniteFieldElement<P>& operator*=(const FiniteFieldElement<P>& ffe1) {
                i_ = (i_*ffe1.i())%P;
                return *this;
            }

            friend bool operator==(const FiniteFieldElement<P>& ffe1,const FiniteFieldElement<P>& ffe2) {
                return (ffe1.i_ == ffe2.i_);
            }

            friend bool operator==(const FiniteFieldElement<P>& ffe1,int i) {
                return (ffe1.i_ == i);
            }

            friend bool operator!=(const FiniteFieldElement<P>& ffe1,const FiniteFieldElement<P>& ffe2) {
                return (ffe1.i_ != ffe2.i_);
            }

            friend bool operator!=(const FiniteFieldElement<P>& ffe1,int i) {
                return (ffe1.i_ != i);
            }

            friend FiniteFieldElement<P> operator/(const FiniteFieldElement<P>& ffe1,const FiniteFieldElement<P>& ffe2) {
                return ( FiniteFieldElement<P>(ffe1.i_ * InvMod(ffe2.i_,P)) );
            }

            friend FiniteFieldElement<P> operator+(const FiniteFieldElement<P>& ffe1, const FiniteFieldElement<P>& ffe2){
                return ( FiniteFieldElement<P>(ffe1.i_ + ffe2.i_) );
            }

            friend FiniteFieldElement<P> operator-(const FiniteFieldElement<P>& ffe1, const FiniteFieldElement<P>& ffe2) {
                return ( FiniteFieldElement<P>(ffe1.i_ - ffe2.i_));
            }

            friend FiniteFieldElement<P> operator+(const FiniteFieldElement<P>& ffe,int i) {
                return FiniteFieldElement<P>(ffe.i_ + i);
            }

            friend FiniteFieldElement<P> operator+(int i,const FiniteFieldElement<P>& ffe) {
                return FiniteFieldElement<P>(ffe.i_ + i);
            }

            friend FiniteFieldElement<P> operator*(int i,const FiniteFieldElement<P>& ffe) {
                return FiniteFieldElement<P>(ffe.i_*i);
            }

            friend FiniteFieldElement<P> operator*(const FiniteFieldElement<P>& ffe,int i) {
                return FiniteFieldElement<P>(ffe.i_*i);
            }

            friend FiniteFieldElement<P> operator*(const FiniteFieldElement<P>& ffe1,const FiniteFieldElement<P>& ffe2) {
                return FiniteFieldElement<P>(ffe1.i_*ffe2.i_);
            }

            template<int T> friend  ostream&    operator<<(ostream& os, const FiniteFieldElement<T>& g) {
                                                return os << g.i_;
                                        }

    };

    template<int P> class EllipticCurve {
        public:
        typedef FiniteFieldElement<P> ffe_t;

        class Point {

            friend class EllipticCurve<P>;
            typedef FiniteFieldElement<P> ffe_t;
            ffe_t x_;
            ffe_t y_;
            EllipticCurve *ec;
            public:
            Point(int x,int y): x_(x), y_(y), ec(0) {}
            Point(const ffe_t& x,const ffe_t& y): x_(x), y_(y), ec(0) {}
            Point(int x,int y,EllipticCurve<P>& ec): x_(x), y_(y), ec(&ec) {}
            Point(const ffe_t& x,const ffe_t& y,EllipticCurve<P>& ec): x_(x), y_(y), ec(&ec) {}
            Point(const Point& e) {
                x_ = e.x_;
                y_ = e.y_;
                ec = e.ec;
            }
            // cong 2 diem tren duong cong

            void add(ffe_t x1,ffe_t y1,ffe_t x2,ffe_t y2,ffe_t& xR,ffe_t& yR) const {

                if(x1 == 0 && y1 == 0) {
                    xR = x2;
                    yR = y2;
                    return;
                }

                if(x2 == 0 && y2 == 0) {
                    xR = x1;
                    yR = y1;
                    return;
                }

                if(y1 == -y2) {
                    xR = yR = 0;
                    return;
                }

                ffe_t s;

                //addtions
                if(x1 == x2 && y1 == y2) {
                    // P + P
                    s = (3*x1.i()*x1.i() + ec->a())/(2*y1);
                    xR = (s*s) - 2*x1;
                }else {
                    // P + Q
                    s = (y2 - y1)/(x2 - x1);
                    xR = (s*s) - x1 - x2;
                }

                if(s!=0) {
                    yR = s*(x1 - xR) - y1;
                }else {
                    xR = yR = 0;
                }
            }

            Point& operator=(const Point& rp) {
                x_ = rp.x_;
                y_ = rp.y_;
                ec = rp.ec;
                return *this;
            }

            // tra ve cac phan tu cua x_ vaf y_ trong elliptic curve

            ffe_t x() const {return x_;}
            ffe_t y() const {return y_;}

            unsigned int   Order(unsigned int maxPeriod = ~0) const {
                          Point r = *this;
                          unsigned int n = 0;
                          while( r.x_ != 0 && r.y_ != 0 )
                          {
                              ++n;
                              r += *this;
                              if ( n > maxPeriod ) break;
                          }
                          return n+1;
                      }

            Point operator-() {
                return Point(x_,-y_);
            }

            friend bool operator==(const Point& lp,const Point& rp) {
                return (lp.ec == rp.ec) && (lp.x_ == rp.x_) && (lp.y_ == rp.y_);
            }

            friend bool operator!=(const Point& lp,const Point& rp) {
                return (lp.ec != rp.ec) || (lp.x_ != rp.x_) || (lp.y_ != rp.x_);
            }

            friend Point operator+(const Point& lp,const Point& rp) {
                  ffe_t xR,yR;
                  lp.add(lp.x_,lp.y_,rp.x_,rp.y_,xR,yR);
                  return Point(xR,yR,*lp.ec);
            }

            Point& operator+=(const Point& rp) {
                add(x_,y_,rp.x_,rp.y_,x_,y_);
                return *this;
            }

            // adddouble return (2^m)*P

            void addDouble(int m,Point& ace) {

                if(m > 0) {
                    Point r = ace;
                    for(int i = 0;i < m;i++) {
                        r += r;
                    }
                    ace = r;
                }
            }

            Point scalarMultiply(int k, const Point& a) {

                Point acc = a;
                Point res = Point(0,0,*ec);
                int i  = 0,j = 0;
                int b = k;
                while(b) {

                    if(b&1) {
                        addDouble(i-j,acc);
                        res += acc;
                        j = i;
                    }
                    b >>= 1;
                    i++;
                }
                return res;
            }

            friend Point operator*(int k,const Point& rp) {
                 return Point(rp).operator*=(k);
            }

            Point& operator*=(int k) {
                return (*this = scalarMultiply(k, *this));
            }

            friend ostream& operator<<(ostream& os, const Point& p) {
                return (os << "(" << p.x_ << ", " << p.y_ << ")");
            }


        };

        // elliptic curve thuc hien
        typedef EllipticCurve<P> this_t;
        typedef class EllipticCurve<P>::Point point_t;

        // tra ve tham so a cua duong cong

        FiniteFieldElement<P> a() const {
            return a_;
        }

        // tra ve tham so b cua duong cong

        FiniteFieldElement<P> b() const {
            return b_;
        }


         // Initialize EC as y^2 = x^3 + ax + b
        EllipticCurve(int a,int b): a_(a),b_(b),m_table_t(),table_filled(false){

        }
/*
        friend bool CheckPointOnEllipticCurve(const Point& ace) {

            int req = (ace.x().i()*ace.x().i()*ace.x().i() + this->a().i()*ace.x().i() + this->b().i() )%P;
            int leq = (ace.y().i()*ace.y().i())%P;
            if(req == leq) return true;
            return false;

        }
*/
        void CalculatePoints() {
            int x_val[P];
            int y_val[P];
            for(int n = 0 ;n < P;n++) {

                int nsq = n*n;
                x_val[n] = ((n*nsq) + a_.i()*n + b_.i()) % P;
                y_val[n] = nsq % P;
            }

            for(int i = 0;i < P;i++) {
                for(int j = 0;j < P;j++) {

                    if(x_val[i] == y_val[j]) {
                        m_table_t.push_back(Point(i,j,*this));
                    }
                }
            }
            table_filled = true;
        }

        // lay phan tu point o vi tri n

        Point operator[](int n) {
            if(!table_filled) {
                CalculatePoints();
            }
            return m_table_t[n];
        }

        // return size cuar group  elliptic curve

        size_t Size() const {
            return m_table_t.size();
        }

        //  retun degree P

        int Degree() const {return P;}

        template<int T> friend ostream& operator<<(ostream& os,const EllipticCurve<T>& EllipticCurve);
        ostream& PrintTable(ostream& os,int colum = 4);

        private:

            FiniteFieldElement<P> a_;  // tham so a cua duong cong
            FiniteFieldElement<P> b_;  // tham so p cuar duong cong
            typedef vector<Point> table_t;
            table_t m_table_t;      // chua cac diem cua duong cong
            bool table_filled;   // neu bang da tinh


        };
    //    template<int T> typename EllipticCurve<T>::Point EllipticCurve<T>::Point::ONE(0,0);
        template<int T> ostream& operator<<(ostream& os,const EllipticCurve<T>& EllipticCurve) {

            os << "y^2 mod " << T << " = (x^3"  << showpos;
            if(EllipticCurve.a_ != 0) {
                os << EllipticCurve.a_ << "x";
            }

            if(EllipticCurve.b_ != 0) {
                os << EllipticCurve.b_ ;
            }

            os << noshowpos << ") mod " << T;
            return os;
        }

        template<int P> ostream& EllipticCurve<P>::PrintTable(ostream& os,int colum) {

            if(table_filled) {

                int col = 0;
                typename EllipticCurve::table_t::iterator iter = m_table_t.begin();
                for(; iter != m_table_t.end();iter++) {
                    os << "(" << (*iter).x_.i() << ", " << (*iter).y_.i() << ")";
                    if(col > colum) {
                        os << "\n";
                        col = 0;
                    }
                }
            }else {
                os << "EllipticCurve, F_" << P;
            }
            return os;
        }

}
