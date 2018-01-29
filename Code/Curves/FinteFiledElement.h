#include<iostream>
#include<ostream>
#include <vector>
#include <NTL/ZZ.h>
#include <cstdlib>
using namespace std;
using namespace NTL;


namespace Cryptography {

    ZZ EGCD(ZZ a, ZZ b, ZZ& u, ZZ &v)
            {
                u = ZZ(1);
                v = ZZ(0);
                ZZ g = a;
                ZZ u1 = ZZ(0);
                ZZ v1 = ZZ(1);
                ZZ g1 = b;
                while (g1 != 0)
                {
                    ZZ q = g/g1; // Integer divide
                    ZZ t1 = u - q*u1;
                    ZZ t2 = v - q*v1;
                    ZZ t3 = g - q*g1;
                    u = u1; v = v1; g = g1;
                    u1 = t1; v1 = t2; g1 = t3;
                }

                return g;
            }

            ZZ InvMod_n(ZZ x, ZZ n) // Solve linear congruence equation x * z == 1 (mod n) for z
            {
                //n = Abs(n);
                x = x % n; // % is the remainder function, 0 <= x % n < |n|
                ZZ u,v,g,z;
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

    class FiniteFieldElement {
        public:
            ZZ P;
            ZZ i_;
            void assign (ZZ j) {
                i_ = j;
                if(j < 0) {
                i_ = (j%P) + 2*P;
                }

                i_ %= P;
            }
            // Contructor
            FiniteFieldElement(): i_(ZZ(0)),P(ZZ(0)){}
            // contructor
            FiniteFieldElement(ZZ i,ZZ P) {
                this->P = P;
                assign(i);
            }
            FiniteFieldElement(ZZ P): i_(ZZ(0)){
                this->P = P;
            }
            // Copy
            FiniteFieldElement(const FiniteFieldElement& ffe1): i_(ffe1.i_), P(ffe1.P){}

            ZZ i() const {
                return i_;
            }
            ZZ p() const {
                return P;
            }

            FiniteFieldElement operator-() const {
                return FiniteFieldElement(-i_,P);
            }

            FiniteFieldElement& operator=(ZZ i) {
                assign(i);
                return *this;
            }

            FiniteFieldElement& operator=(const FiniteFieldElement& ffe1) {
                this->i_ = ffe1.i_;
                this->P  = ffe1.P;
                return *this;
            }

            FiniteFieldElement& operator*=(const FiniteFieldElement& ffe1) {
                if(this->P == ffe1.P)
                    i_ = (i_*ffe1.i())%this->P;
                return *this;
            }

            friend bool operator==(const FiniteFieldElement& ffe1,const FiniteFieldElement& ffe2) {
                if(ffe1.P == ffe2.P)
                    return (ffe1.i_ == ffe2.i_);
                return false;
            }

            friend bool operator==(const FiniteFieldElement& ffe1,ZZ i) {
                return (ffe1.i_ == i);
            }

            friend bool operator!=(const FiniteFieldElement& ffe1,const FiniteFieldElement& ffe2) {
                if(ffe1.P == ffe2.P)
                    return (ffe1.i_ != ffe2.i_);
                return false;
            }

            friend bool operator!=(const FiniteFieldElement& ffe1,ZZ i) {
                return (ffe1.i_ != i);
            }

            friend FiniteFieldElement operator/(const FiniteFieldElement& ffe1,const FiniteFieldElement& ffe2) {
                if(ffe1.P == ffe2.P)
                    return ( FiniteFieldElement(ffe1.i_ *InvMod_n(ffe2.i_,ffe1.P),ffe1.P));
                else
                    return FiniteFieldElement();
            }

            friend FiniteFieldElement operator+(const FiniteFieldElement& ffe1, const FiniteFieldElement& ffe2){
                if(ffe1.P == ffe2.P)
                    return ( FiniteFieldElement(ffe1.i_ + ffe2.i_, ffe1.P) );
                else
                    return FiniteFieldElement();
            }

            friend FiniteFieldElement operator-(const FiniteFieldElement& ffe1, const FiniteFieldElement& ffe2) {
                if(ffe1.P == ffe2.P)
                    return (FiniteFieldElement(ffe1.i_ - ffe2.i_,ffe1.P));
                else
                    return FiniteFieldElement();
            }

            friend FiniteFieldElement operator+(const FiniteFieldElement& ffe,ZZ i) {
                    return FiniteFieldElement(ffe.i_ + i,ffe.P);
            }

            friend FiniteFieldElement operator+(ZZ i,const FiniteFieldElement& ffe) {
                return FiniteFieldElement(ffe.i_ + i,ffe.P);
            }

            friend FiniteFieldElement operator*(ZZ i,const FiniteFieldElement& ffe) {
                return FiniteFieldElement(ffe.i_*i,ffe.P);
            }

            friend FiniteFieldElement operator*(const FiniteFieldElement& ffe,ZZ i) {
                return FiniteFieldElement(ffe.i_*i,ffe.P);
            }

            friend FiniteFieldElement operator*(const FiniteFieldElement& ffe1,const FiniteFieldElement& ffe2) {
                if(ffe1.P == ffe2.P)
                    return FiniteFieldElement(ffe1.i_*ffe2.i_,ffe1.P);
                else
                    return FiniteFieldElement();
            }

            friend  ostream&    operator<<(ostream& os, const FiniteFieldElement& g) {
                                                return os << g.i_;
            }
    };

    class EllipticCurve {
        public:
            ZZ P;
            0;
        class Point {
            public:
            ZZ P;
            friend class EllipticCurve;
            typedef FiniteFieldElement ffe_t;
            ffe_t x_;
            ffe_t y_;
            EllipticCurve *ec;
            Point(): x_(),y_(),P(ZZ(0)),ec(0){}
            Point(ZZ x,ZZ y,ZZ s): x_(x,s), y_(y,s),P(s), ec(0) {}
            Point(const ffe_t& x,const ffe_t& y): x_(x), y_(y), ec(0) {
                this->P = x.p();
            }
            Point(ZZ x,ZZ y,EllipticCurve& ec): x_(x,ec.Degree()), y_(y,ec.Degree()), ec(&ec) {
                this->P = ec.Degree();
            }
            Point(const ffe_t& x,const ffe_t& y,EllipticCurve& ec): x_(x), y_(y), ec(&ec) {
                this->P = x.P;
            }
            Point(const Point& e) {
                x_ = e.x_;
                y_ = e.y_;
                P =  e.P;
                ec = e.ec;
            }

            // cong 2 diem tren duong cong
            void add(ffe_t x1,ffe_t y1,ffe_t x2,ffe_t y2,ffe_t& xR,ffe_t& yR) const {
                if(x1 == ZZ(0) && y1 == ZZ(0)) {
                    xR = x2;
                    yR = y2;
                    return;
                }

                if(x2 == ZZ(0) && y2 == ZZ(0)) {
                    xR = x1;
                    yR = y1;
                    return;
                }

                if(y1 == -y2) {
                    xR = yR = ZZ(0);
                    return;
                }

                ffe_t s;

                //addtions
                if(x1 == x2 && y1 == y2) {
                    // P + P
                    s = (ZZ(3)*x1.i()*x1.i() + ec->a())/(ZZ(2)*y1);
                    xR = (s*s) - ZZ(2)*x1;
                }else {
                    // P + Q
                    s = (y2 - y1)/(x2 - x1);
                    xR = (s*s) - x1 - x2;
                }

                if(s!= ZZ(0)) {
                    yR = s*(x1 - xR) - y1;
                }else {
                    xR = yR = ZZ(0);
                }
            }

            Point& operator=(const Point& rp) {
                x_ = rp.x_;
                y_ = rp.y_;
                P = rp.P;
                ec = rp.ec;
                return *this;
            }

            ffe_t x() const {return x_;}
            ffe_t y() const {return y_;}

            Point operator-() {
                return Point(x_,-y_);
            }

            friend bool operator==(const Point& lp,const Point& rp) {
                if(lp.P == rp.P)
                    return (lp.ec == rp.ec) && (lp.x_ == rp.x_) && (lp.y_ == rp.y_);
                else return false;
            }

            friend bool operator!=(const Point& lp,const Point& rp) {
                if(lp.P == rp.P)
                    return (lp.ec != rp.ec) || (lp.x_ != rp.x_) || (lp.y_ != rp.x_);
                else return true;
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

            // caculator Order of Point P
           unsigned long   Order(unsigned long maxPeriod = ~0) const {
                          Point r = *this;
                          unsigned long n = 0;
                          while( r.x_.i() != 0 && r.y_.i() != 0 )
                          {
                              ++n;
                              r += *this;
                              if ( n > maxPeriod ) break;
                          }
                          return n+1;
                      }


            // add double return (2^m) mod P
            void addDouble(ZZ m,Point& ace) {

                if(m > 0) {
                    Point r = ace;
                    for(ZZ i = ZZ(0);i < m;i++) {
                        r += r;
                    }
                    ace = r;
                }
            }

            Point scalarMultiply(ZZ k, const Point& a) {

                Point acc = a;
                Point res = Point(ZZ(0),ZZ(0),*ec);
                ZZ i  = ZZ(0),j = ZZ(0);
                ZZ b = k;
                while(b > 0) {

                    if((b&1) != 0) {
                        addDouble(i-j,acc);
                        res += acc;
                        j = i;
                    }
                    b >>= 1;
                    i++;
                }
                return res;
            }

            friend Point operator*(ZZ k,const Point& rp) {
                 return Point(rp).operator*=(k);
            }

            Point& operator*=(ZZ k) {
                return (*this = scalarMultiply(k, *this));
            }

            friend ostream& operator<<(ostream& os, const Point& p) {
                return (os << "(" << p.x_ << ", " << p.y_ << ")");
            }

        };
        // Elliptic thuc hien
        typedef EllipticCurve this_t;
        typedef class EllipticCurve::Point point_t;

        // return a
        FiniteFieldElement a() const {
            return a_;
        }

        // return b
        FiniteFieldElement b() const {
            return b_;
        }

        EllipticCurve(ZZ a,ZZ b,ZZ s): a_(a,s),b_(b,s),m_table_t(),table_filled(false){
            this->P = s;
        }

        Point ReturnPoint(const ZZ& x) {
            ZZ yy = power(x,3) + this->a().i()*x + this->b().i();
            ZZ y = SqrRoot(yy);
            return Point(x,y,*this);
        }
/*
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

        Point operator[](int n) {
            if(!table_filled) {
                CalculatePoints();
            }
            return m_table_t[n];
        }

 */     bool CheckPointOnEllipticCurve(const EllipticCurve::Point& ace) {
            if(this->P == ace.P) {
                ffe_t x = ace.x();
                ffe_t y = ace.y();
                ZZ a = (y*y).i()%this->P;
                ZZ b = (x*x*x + this->a()*x + this->b()).i()%this->P;
                if(a == b) return true;
            }
            return false;
        }


        ZZ Degree() const {return P;}
        friend ostream& operator<<(ostream& os,const EllipticCurve& EllipticCurve) {
            os << "y^2 mod " << EllipticCurve.Degree() << " = (x^3"  << showpos;
            if(EllipticCurve.a_ != ZZ(0)) {
                os << EllipticCurve.a_ << "x";
            }

            if(EllipticCurve.b_ != ZZ(0)) {
                os << EllipticCurve.b_ ;
            }

            os << noshowpos << ") mod " << EllipticCurve.Degree();
            return os;
        }


        ostream& PrintTable(ostream& os,int colum = 4);
        private:
            FiniteFieldElement a_;  // tham so a cua duong cong
            FiniteFieldElement b_;  // tham so p cuar duong cong
            typedef vector<Point> table_t;
            table_t m_table_t;      // chua cac diem cua duong cong
            bool table_filled;   // neu bang da tinh
        };
/*
        ZZ Sqrt(const ZZ& n) {

            if(n <= 1) {
                return n;
            }

            ZZ delta(0),x0(1),x1(0),x2(0);
            while(true) {
                delta = n / x0;
                x1 = (x0 + delta)/2;
                if(delta == 0) return x1;

                x0 = x1;
                x2 = x0*x0;

                if(x2 >= n) {

                    if(x2 == n) {
                        return x0;
                    }
                    x0--;
                    x2 = x0*x0;

                    while(x2 >= n) {
                        x0--;
                        x2 = x0*x0;
                    }
                    return x0;
                }
            }
        }
        */
        ZZ Sqrt(const ZZ& n) {
            if(n == 0) return ZZ(0);
            ZZ n1 = (n >> 1) + 1;
            ZZ n2 = (n1 + (n/n1)) >> 1;
            while(n2 < n1) {
                n1 = n2;
                n2 = (n1 + (n/n1)) >> 1;
            }
            return n1;
        }

        typedef vector<EllipticCurve::Point> table_t;
        table_t table_m;

        ZZ Jacobi1(ZZ x,ZZ p) {
            ZZ a = x;
            ZZ b = p;
            cout << "a is: " << x <<endl;
            cout << "b is: " << p << endl;
            if(b <=0 || (b%2 == 0)) return ZZ(0);
            ZZ j(1);
            if(a < 0) {
                a = (-1)*a;
              //  cout << "a is: " << a << endl;
                if((b%4) == 3) j = -j;
                while(a!=0) {
                    while((a%2) == 0) {
                        a = a/2;
                        if(((b%8) == 3) ||((b%8)== 5 ))
                            j = -j;
                    }
                    ZZ c = b;
                    b = a;
                    a = c;
                    if(((a%4) == 3) && ((b%4) == 3)) j =-j;
                    a = a%b;
                }
                if(b == 1) return j;
                else return ZZ(0);
            }
        }



        bool checkPoint(EllipticCurve::Point &a,ZZ &s) {
            //cout << table_m.size() <<endl;
            for(long i= 0; i < table_m.size();i++) {
            //    cout << "a is: " << a << endl;
             //   cout << "table_m[i] is: " << table_m[i] <<endl;
                if(a == table_m[i]) {
                    s = ZZ(i);
                    return true;
                }
            }
            return false;

        }

        ZZ convert(const ZZ &u,const ZZ &p) {
                ZZ s = u/p + 1;
                //cout << "s is: " << s << endl;
                return(p*s - u);
            return ZZ(1);
        }


        ZZ BaByStepGiantStep(const ZZ&n,EllipticCurve::Point P, EllipticCurve::Point Q) {
            // 1,
            ZZ u = Sqrt(n) + 1;
            //EllipticCurve::Point S = P;
            //2,
            EllipticCurve::Point R(ZZ(0),ZZ(0),*(P.ec));
            for(ZZ i = ZZ(0); i <= (u/2)- 1;i++) {
                table_m.push_back(R);
                R = R + ZZ(2)*P;
            }


            // 3,
            long alpha = Jacobi(Q.x().i(),Q.P);
            ZZ t;
            //cout  << alpha << endl;
            if(alpha == -1) {
                Q = Q + (-P);
              //  cout << Q <<endl;
                t = ZZ(1);
            }else {
                Q = Q;
                t = ZZ(0);
            }


            EllipticCurve::Point R1 = convert(u,Q.P)*P;
            cout << "-u is:" << convert(u,Q.P) << endl;
            cout << "R1 is: " << R1 << endl;
            EllipticCurve::Point R2 = Q;
           // cout << R2 << endl;

            for(ZZ j(1); j <= u - 1;j++) {
                cout <<"-----"<<endl;
                ZZ i(0);
                if(checkPoint(R2,i)) {
                    cout << "i is: " << i<< endl;
                    cout << "j is: " << j << endl;
                    cout << "t is: " << t << endl;
                    return (2*i + j*u + t);
                }
                R2 = R2 + R1;
            }
            return ZZ(0);
        }

    ZZ convertToDecnum(string hex) {

        int length = hex.size();
        const ZZ base = ZZ(16);
        ZZ decnum = ZZ(0);
        int i;
        for(int i = 0;i < length;i++) {
            // compare hex with ASCII values
            if(hex.at(i) >= 48 && hex.at(i) <= 57) // gia tri between 0-9
            {
                decnum += ((int)hex.at(i) - 48)*power(base,length - i -1);
            }else if(hex.at(i) >= 65 && hex.at(i) <= 70) { // gia tri between A-F
                decnum += ((int)hex.at(i) - 55)*power(base,length - i -1);
            }else if(hex.at(i) >= 97 && hex.at(i) <= 102) { // gia tri nawm between a-f
                decnum += ((int)hex.at(i) - 87)*power(base,length - i -1);
            }
            else {
                cout << "Invalid Hexadecimal number \n";
            }
        }
        return decnum;
    }

}
