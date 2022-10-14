
//Highly hide the winsock details, especially because it has select that conflicts with mingw
//Link level this must be dynamically linked, not staticly linked
class SockSimple{
public:
    SockSimple();
    ~SockSimple();
    int WaitForConnection();
    int ReceiveData(void * buffer, const int buffer_len);
    int Close();
private:
    struct SockSimpleDataStruct;
    SockSimpleDataStruct * _data;
};
