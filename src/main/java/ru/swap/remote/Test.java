package ru.swap.remote;

import com.google.gson.Gson;
import lombok.extern.log4j.Log4j2;
import ru.swap.server.security.permissions.Subject;
import ru.swap.server.security.permissions.SubjectList;

import java.io.FileReader;
import java.io.IOException;
import java.util.List;

@Log4j2
public class Test {

    private static List<Subject> subjects;

//    public static void main(String[] args) {
//        ObjectMapper mapper = new ObjectMapper();
//        try {
//            subjects = mapper.readValue(new FileInputStream(new File("E:/permissions.json")), new TypeReference<List<Subject>>() {
//            });
//        } catch (
//                IOException e) {
//            log.error("[GridSecurityProcessorImpl] Exception loading subjects: " + e.getMessage());
//        }
//        System.out.println(subjects);
//    }
    public static void main(String[] args) {
        try {
            SubjectList list = new Gson().fromJson(new FileReader("E:/permissions.json"), SubjectList.class);
            System.out.println(list.getSubjects().get(0));
            System.out.println(list.getSubjects().get(1));
        } catch (
                IOException e) {
            log.error("[GridSecurityProcessorImpl] Exception loading subjects: " + e.getMessage());
        }

    }

}
