package pt.unl.fct.di.apdc.firstwebapp.util;

public class AdditionalData {

    public String typeOfAccount;
    public String phone;
    public String mobilePhone;
    public String occupation;
    public String workPlace;
    public String address;
    public String nif;

    public AdditionalData() {
    }

    public AdditionalData( String typeOfAccount, String phone, String mobilePhone,
                        String occupation, String workPlace, String address, String nif) {

        this.typeOfAccount = typeOfAccount;
        this.phone = phone;
        this.mobilePhone = mobilePhone;
        this.occupation = occupation;
        this.workPlace = workPlace;
        this.address = address;
        this.nif = nif;
    }
}
