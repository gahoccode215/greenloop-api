package com.greenloop.event.utils;


import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class CSVExportUtil {

    private static final DateTimeFormatter FILENAME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    /**
     * Chuẩn bị response cho CSV export với UTF-8 BOM
     * @param response HttpServletResponse
     * @param filename Tên file (không có extension)
     * @throws IOException
     */
    public static void prepareCsvResponse(HttpServletResponse response, String filename) throws IOException {
        response.setContentType("text/csv; charset=UTF-8");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Content-Disposition",
                "attachment; filename=" + filename + "_" +
                        LocalDateTime.now().format(FILENAME_FORMATTER) + ".csv");

        // Write UTF-8 BOM để Excel nhận diện tiếng Việt
        response.getOutputStream().write(0xEF);
        response.getOutputStream().write(0xBB);
        response.getOutputStream().write(0xBF);
    }

    /**
     * Tạo CSV Writer với encoding đúng
     * @param response HttpServletResponse
     * @return OutputStreamWriter
     * @throws IOException
     */
    public static OutputStreamWriter createCsvWriter(HttpServletResponse response) throws IOException {
        return new OutputStreamWriter(response.getOutputStream(), StandardCharsets.UTF_8);
    }

    /**
     * Tạo CSVPrinter với headers
     * @param writer OutputStreamWriter
     * @param headers Danh sách headers
     * @return CSVPrinter
     * @throws IOException
     */
    public static CSVPrinter createCsvPrinter(OutputStreamWriter writer, String... headers) throws IOException {
        return new CSVPrinter(writer, CSVFormat.DEFAULT.withHeader(headers));
    }

    /**
     * Handle error response
     * @param response HttpServletResponse
     * @param errorMessage Error message
     * @throws IOException
     */
    public static void handleError(HttpServletResponse response, String errorMessage) throws IOException {
        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        response.setContentType("application/json; charset=UTF-8");
        response.getWriter().write("{\"error\":\"" + errorMessage + "\"}");
    }
}
